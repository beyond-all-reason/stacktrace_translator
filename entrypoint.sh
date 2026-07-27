#!/bin/sh
# Start both services in a single container:
#   1. the XML-RPC translation backend on :8000 (for external services + the frontend)
#   2. the Dash web frontend on :8050 (published on host port 80)
#
# If either process stops the script exits so Docker's `restart` policy can
# recreate the container.
set -e

cd /usr/src/app

# XML-RPC backend, logging to stdout and a file.
# Run from /usr/src/app so the script dir (python-server) is on sys.path,
# matching the original single-service behaviour.
python3 python-server/stacktrace_translator.py 2>&1 | tee /usr/src/app/logs/output.log &
backend_pid=$!

# Dash frontend under gunicorn.
gunicorn \
    --chdir /usr/src/app/dash-frontend \
    --bind 0.0.0.0:8050 \
    --workers 2 \
    --timeout 120 \
    app:server &
frontend_pid=$!

# Forward termination signals so both processes shut down cleanly.
trap 'kill "$backend_pid" "$frontend_pid" 2>/dev/null' TERM INT

# Exit as soon as either process stops.
while kill -0 "$backend_pid" 2>/dev/null && kill -0 "$frontend_pid" 2>/dev/null; do
    sleep 5
done

kill "$backend_pid" "$frontend_pid" 2>/dev/null
exit 1

