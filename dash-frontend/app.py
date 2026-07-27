#!/usr/bin/env python3
"""
Dash frontend for the Spring/Recoil stacktrace translator.

Replaces the former PHP/Apache frontend. It provides a small web UI that
accepts an infolog.txt (via URL or paste), forwards it to the Python XML-RPC
backend (``translate_stacktrace``) and renders the translated frames with
links to the matching source lines on GitHub.
"""

import os
import re
import time
import xmlrpc.client

import requests
from dash import Dash, html, dcc, Input, Output, State, no_update

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# XML-RPC backend that exposes translate_stacktrace (runs in the same container).
TRANSLATOR_URL = os.environ.get("TRANSLATOR_URL", "http://127.0.0.1:8000")

# Maximum number of bytes downloaded from a remote infolog URL.
MAX_DOWNLOAD_BYTES = 1_000_000

# Minimum number of seconds between two translation requests (rate limiting).
RATE_LIMIT_SECONDS = 10

# Port the Dash/Flask server listens on inside the container.
LISTEN_PORT = int(os.environ.get("PORT", "8050"))

# ---------------------------------------------------------------------------
# infolog parsing helpers (ported from the old index.php)
# ---------------------------------------------------------------------------

_RE_VERSION = re.compile(
    r"(Spring ([0-9]+\.[0-9]+)(\.\d*-\d*-g([0-9a-f]{7})\s)?(\w*)\s?(\((.*)\))?)(\n)"
)

_RE_URL = re.compile(r"^https?://[a-z0-9-]+(\.[a-z0-9-]+)*(:[0-9]+)?(/.*)?$", re.IGNORECASE)

_RE_RTS_PATH = re.compile(r".*(rts/.*)")


def get_version(infolog: str) -> str:
    """Return the full Spring version string found in the infolog, or ''."""
    m = _RE_VERSION.search(infolog)
    return m.group(1) if m else ""


def get_commit(infolog: str) -> str:
    """Return the 7-char commit hash found in the infolog, or ''."""
    m = _RE_VERSION.search(infolog)
    return (m.group(4) or "") if m else ""


def get_branch(infolog: str) -> str:
    """Return the branch name found in the infolog, defaulting to master/develop."""
    m = _RE_VERSION.search(infolog)
    if not m:
        return "develop"
    branch = m.group(5)
    return branch if branch else "master"


def is_valid_url(url: str) -> bool:
    """True for http(s) URLs, False for anything local."""
    return bool(_RE_URL.match(url))


def normalize_infolog(text: str) -> str:
    """Normalize line endings the same way the old PHP frontend did."""
    text = text.replace("\r\n", "\n")
    text = text.replace("\n\n", "\n")
    return text


def fetch_remote_infolog(url: str) -> str:
    """Download a remote infolog, limited to MAX_DOWNLOAD_BYTES."""
    resp = requests.get(url, timeout=30, stream=True)
    resp.raise_for_status()
    return resp.raw.read(MAX_DOWNLOAD_BYTES, decode_content=True).decode(
        "utf-8", errors="replace"
    )


# ---------------------------------------------------------------------------
# XML-RPC call + result rendering
# ---------------------------------------------------------------------------


def translate(infolog: str):
    """Call the XML-RPC backend and return the list of translated frames."""
    proxy = xmlrpc.client.ServerProxy(TRANSLATOR_URL)
    return proxy.translate_stacktrace(infolog)


def build_results(frames, version: str, commit: str):
    """Turn the raw XML-RPC result into Dash components (table + plain text)."""
    header = html.Tr(
        [html.Th("module"), html.Th("address"), html.Th("file"), html.Th("line")]
    )
    rows = []
    clean_lines = []

    for frame in frames:
        module, address, filename, line = frame[0], frame[1], frame[2], frame[3]

        if filename:
            m = _RE_RTS_PATH.match(filename)
            if m and m.group(1):
                filename = m.group(1)

        clean_lines.append(f"{module} {address} {filename}:{line}")

        # Only source files (rts/...) get a GitHub link.
        if filename and filename[0] == "r":
            if commit:
                href = (
                    "https://github.com/beyond-all-reason/spring/blob/BAR105/"
                    f"{filename}#L{line}"
                )
            else:
                href = (
                    "https://github.com/beyond-all-reason/RecoilEngine/tree/master/"
                    f"{filename}#L{line}"
                )
            line_cell = html.Td(html.A(str(line), href=href, target="_blank"))
        else:
            line_cell = html.Td(str(line))

        rows.append(
            html.Tr(
                [
                    html.Td(module),
                    html.Td(address),
                    html.Td(filename),
                    line_cell,
                ]
            )
        )

    clean_text = "\n".join(clean_lines)

    return html.Div(
        [
            html.H1(f"translated with links to github source ('{version}' detected)"),
            html.Table([header] + rows),
            html.H1("translated for copy and paste"),
            html.Pre(clean_text),
        ]
    )


# ---------------------------------------------------------------------------
# Dash app
# ---------------------------------------------------------------------------

app = Dash(__name__, title="Spring RTS - stacktrace translator frontend")
server = app.server  # exposed for gunicorn

# Simple in-process rate limiter shared across requests.
_last_run = {"ts": 0.0}

app.layout = html.Div(
    [
        html.P(
            [
                "This page is a simple frontend for ",
                html.A(TRANSLATOR_URL, href=TRANSLATOR_URL),
                html.Br(),
                "Use a url or copy and paste into this form to translate the "
                "infolog.txt of a crashed spring.",
                html.Br(),
                f"At max {MAX_DOWNLOAD_BYTES:,} bytes are downloaded!",
                html.Br(),
                html.B("Note: only windows-versions can be translated."),
            ]
        ),
        html.P("Url of unformatted raw plaintext infolog.txt"),
        dcc.Input(id="url", type="text", style={"width": "40em"}, placeholder="https://..."),
        html.P("or copy and paste here:"),
        dcc.Textarea(id="infolog", style={"width": "100%", "height": "20em"}),
        html.Br(),
        html.Button("Submit", id="submit", n_clicks=0),
        dcc.Loading(html.Div(id="results"), type="default"),
    ],
    style={"fontFamily": "arial", "fontSize": "12px", "maxWidth": "80em", "margin": "1em auto"},
)


@app.callback(
    Output("results", "children"),
    Input("submit", "n_clicks"),
    State("url", "value"),
    State("infolog", "value"),
    prevent_initial_call=True,
)
def on_submit(_n_clicks, url, infolog):
    url = (url or "").strip()
    infolog = infolog or ""

    # Resolve the infolog contents from URL or pasted text.
    if url:
        if not is_valid_url(url):
            return html.Div("Invalid url!", style={"color": "red"})
        try:
            infolog = fetch_remote_infolog(url)
        except requests.RequestException as exc:
            return html.Div(f"Could not fetch url: {exc}", style={"color": "red"})

    if not infolog.strip():
        return no_update

    infolog = normalize_infolog(infolog)

    # Rate limiting.
    now = time.time()
    wait = int(_last_run["ts"] + RATE_LIMIT_SECONDS - now)
    if wait > 0:
        return html.Div(
            f"Please wait {wait} seconds to rerun this script.",
            style={"color": "red"},
        )
    _last_run["ts"] = now

    try:
        frames = translate(infolog)
    except xmlrpc.client.Fault as fault:
        return html.Div(
            [
                html.P(f"Error: {fault.faultString}"),
                html.P(
                    "Maybe this stacktrace is from a self-compiled spring, or is "
                    "the stack-trace too old? This script only can handle >= 0.82."
                ),
            ],
            style={"color": "red"},
        )
    except (xmlrpc.client.ProtocolError, OSError) as exc:
        return html.Div(f"Could not reach translator: {exc}", style={"color": "red"})

    version = get_version(infolog)
    commit = get_commit(infolog)
    return build_results(frames, version, commit)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=LISTEN_PORT)
