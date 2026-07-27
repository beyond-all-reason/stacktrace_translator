# syntax=docker/dockerfile:1
#
# Single image that runs BOTH:
#   - the XML-RPC translation backend  (port 8000, reachable by external services)
#   - the Dash web frontend            (port 8050, published on host port 80)
#
# This replaces the previous split of a Debian/Python "python-server" image and a
# separate PHP/Apache frontend image with one small Python-only image.

FROM debian:12

# System tools required by the translator backend (addr2line, 7za, ...).
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 python3-pip python3-pefile binutils wget p7zip-full git curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

# Python dependencies: backend (pefile, zstandard) + frontend (dash, requests, gunicorn).
COPY dash-frontend/requirements.txt ./dash-frontend/requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages \
        pefile zstandard -r ./dash-frontend/requirements.txt

# Application code.
COPY python-server/ ./python-server/
COPY dash-frontend/ ./dash-frontend/
COPY entrypoint.sh ./entrypoint.sh
RUN chmod +x ./entrypoint.sh && mkdir -p /usr/src/app/logs

# 8000: XML-RPC backend (external services)   8050: Dash frontend
EXPOSE 8000 8050

CMD ["./entrypoint.sh"]
