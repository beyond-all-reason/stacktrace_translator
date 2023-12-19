# syntax=docker/dockerfile:1

# Use Debian 12 as the base image
FROM debian:12

# Update the package list and install Python
RUN apt-get update && apt-get install -y python3 python3-pip python3-pefile binutils wget binutils p7zip-full git

# Set the working directory inside the container
WORKDIR /usr/src/app

# I have decided for these to be runtime stuff for freshness
RUN git clone https://github.com/beyond-all-reason/stacktrace_translator.git
RUN cp -R ./stacktrace_translator/* .

#If you are locally changing the files for the translator while building the image, enable these two lines: 
# COPY stacktrace_translator.py .
# COPY update_debug_symbols.py .

# The stacktrace translator listens on 8000
EXPOSE 8000

# Run the script when the container starts
CMD ["git","clone", "https://github.com/beyond-all-reason/stacktrace_translator.git"]
CMD ["cp","-R","./stacktrace_translator/*","."]
CMD ["python3", "stacktrace_translator.py"]

# just start the interpreter so the image doesnt immediately exit
# CMD ["python3"]

# build this image with:
# docker build  -t stacktraceimg:v02 .


#interactively run with a shell and expose the port:
# docker run -p 127.0.0.1:8000:8000 -it stacktraceimg:v02 /bin/bash

# just run and expose the port, -d is used so that it runs in background
# docker run -d -p 127.0.0.1:8000:8000 stacktraceimg:v02

# To stop the image, find the Container ID with docker ps, then sudo docker stop CONTAINERID 
# this does not work, permission denied
