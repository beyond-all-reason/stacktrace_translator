# stacktrace_translator
Web-based frontend for translating stack traces of SpringRTS engine crashes.

The frontend is a lightweight [Dash](https://dash.plotly.com/) (Python) app that
talks to the Python XML-RPC backend. It replaces the previous PHP/Apache
frontend, giving a smaller footprint (a single Python stack instead of PHP +
Apache + Python).

# Requirements:
- Docker
- docker-compose

# Installation:
1. Clone the repository:
   ```sh
   git clone https://github.com/beyond-all-reason/stacktrace_translator.git
   ```
2. Navigate to the directory:
   ```sh
   cd stacktrace_translator
   ```
3. Build Docker image:
   ```sh
   docker-compose build
   ```
   Or completely rebuild it via (also needs a complete rebuild if git repo has changes!):
   ```sh
   docker-compose build --no-cache
   ```

4. Deploy Docker image:
   ```sh
   docker-compose up
   ```
5. Deployed:
    <a href="http://127.0.0.1:80">
    ```
    http://127.0.0.1:80
    ```
    </a>

## Usage
Use a URL or manually copy and paste into the textbox the `infolog.txt` of a crashed Spring.

### Keep in mind:
- Only Windows versions can be translated.
- At max 100.000 bytes are downloaded.
- The app takes a couple of minutes to process the data.

## Architecture

A single container (built from the root [Dockerfile](Dockerfile)) runs both
services, started by [entrypoint.sh](entrypoint.sh):

- **XML-RPC backend** — core translation logic on port 8000. Published on host
  port 8000 so external services can keep calling `translate_stacktrace`
  directly.
- **Dash frontend** — Dash web UI served by gunicorn on port 8050 (published on
  host port 80). It forwards infologs to the backend on `127.0.0.1:8000` and
  renders the translated frames with GitHub source links. The backend URL is
  configurable via the `TRANSLATOR_URL` environment variable.

`docker-compose` orchestrates this single container, and Docker's
`restart: unless-stopped` policy recovers it if either process exits.

## Local changes

The image copies the local `python-server/` and `dash-frontend/` sources at build
time, so any local edits are picked up on the next build.

Build and run with
```sh
docker-compose build && docker-compose up
```

The frontend is published on host port 80, so open <http://127.0.0.1:80> after
`docker-compose up`. The XML-RPC backend is available on <http://127.0.0.1:8000>.

### Running without Docker

```sh
# backend (needs binutils/addr2line + p7zip installed on the host)
python3 python-server/stacktrace_translator.py   # serves XML-RPC on :8000

# frontend (in another shell)
cd dash-frontend
pip install -r requirements.txt
TRANSLATOR_URL=http://127.0.0.1:8000 python app.py   # serves on :8050
```
Then open <http://127.0.0.1:8050>.