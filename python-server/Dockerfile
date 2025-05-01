# syntax=docker/dockerfile:1

# Use Debian 12 as the base image
FROM debian:12

# Update the package list and install Python
RUN apt-get update && apt-get install -y python3 python3-pip python3-pefile binutils wget binutils p7zip-full git

# Install the required Python packages, zstd:
RUN pip3 install --no-cache-dir --break-system-packages pefile zstandard
# Set the working directory inside the container
WORKDIR /usr/src/app

# I have decided for these to be runtime stuff for freshness
RUN git clone https://github.com/beyond-all-reason/stacktrace_translator.git .

# Local changes:
# COPY python-server/stacktrace_translator.py /python-server
# COPY python-server/update_debug_symbols.py /python-server


# Ensure logs directory exists
RUN mkdir -p /usr/src/app/logs

# Run the script when the container starts and log to both stdout and a file
CMD ["sh", "-c", "python3 python-server/stacktrace_translator.py 2>&1 | tee /usr/src/app/logs/output.log"]


# The stacktrace translator listens on 8000
EXPOSE 8000