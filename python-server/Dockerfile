# syntax=docker/dockerfile:1

# Use Debian 12 as the base image
FROM debian:12

# Update the package list and install Python
RUN apt-get update && apt-get install -y python3 python3-pip python3-pefile binutils wget binutils p7zip-full git

# Set the working directory inside the container
WORKDIR /usr/src/app

# I have decided for these to be runtime stuff for freshness
RUN git clone https://github.com/beyond-all-reason/stacktrace_translator.git .

# Local changes:
# COPY stacktrace_translator.py .
# COPY update_debug_symbols.py .

# Run the script when the container starts
CMD ["python3", "stacktrace_translator.py"]

# The stacktrace translator listens on 8000
EXPOSE 8000