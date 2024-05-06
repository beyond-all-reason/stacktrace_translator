# stacktrace_translator
Web-based frontend for translating stack traces of SpringRTS engine crashes.

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
   Or completely rebuild it via:
   ```sh
   docker-compose build --no-cache
   ```

4. Deploy Docker image:
   ```sh
   docker-compose up
   ```
5. Deployed:
    <a href="http://127.0.0.1:8000">
    ```
    http://127.0.0.1:8000
    ```
    </a>

## Usage
Use a URL or manually copy and paste into the textbox the `infolog.txt` of a crashed Spring.

### Keep in mind:
- Only Windows versions can be translated.
- At max 100.000 bytes are downloaded.
- The app takes a couple of minutes to process the data.

## Local changes

If you are locally changing the files for the translator while building the image, uncomment these two lines in <a href="python-server/Dockerfile">python-server</a>:
```
COPY stacktrace_translator.py .
COPY update_debug_symbols.py .
```
