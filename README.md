# JoePoints - Go Version

This is a Golang conversion of the JoePoints application, a points/rewards system with API authentication, user management, and SQLite database storage.

## Project Structure

joepoints/<br>
├── cmd/joepoints/main.go       # Entry point (package main)<br>
├── internal/<br>
│   ├── api/api.go              # HTTP API handlers<br>
│   ├── server/server.go        # Server setup and request handling<br>
│   ├── db/db.go                # SQLite database operations<br>
│   └── crypto/crypto.go        # Cryptographic functions<br>
├── build/                      # Build artifacts and Dockerfile<br>
├── www/                        # Static HTML/CSS/JS assets<br>
├── C_Original/                 # Original C version (optional)<br>
├── go.mod, go.sum              # Go module definitions<br>
├── README.md, SECURITY.md<br>
└── .gitignore


## Dependencies

- `github.com/mattn/go-sqlite3` - SQLite3 driver for Go

## Building

### Using Go directly

1. Install Go 1.21 or later
2. Navigate to the project root
3. Install dependencies:
   ```bash
   go mod download
   ```
4. Build the application:
   ```bash
   go build -o build/joepoints ./cmd/joepoints
   ```

### Using Mage (Preferred)

1. Install Go 1.21 or later
2. Navigate to the project root
3. Install dependencies:
   ```bash
   go mod download
   ```
4. Install Mage: `go install github.com/magefile/mage@latest`
5. Run the build:
   ```bash
   mage build
   ```

## Running

```bash
./joepoints [-port <port_number>]
```

By default the server will:
* Listen on port 8080
* Use `database/data.db` for the SQLite database
* Serve static files from `www/` directory

## API Endpoints

### Authentication
All POST API endpoints require an `Authorization: Bearer <key>` header.

### Endpoints

- `POST /api/genkey` - Generate a new API key
- `POST /api/addperson` - Add a new user
- `POST /api/removeperson` - Remove a user
- `GET /api/getuid` - Get user ID by name
- `GET /api/getpoints` - Get user's points
- `POST /api/setpoints` - Set user's points
- `POST /api/addpoints` - Add points to user
- `GET /api/getall` - Get all users
- `POST /api/removekey` - Remove current API key

## Features

- **Secure Key Management**: API keys are hashed with PBKDF2-HMAC-SHA256
- **User Management**: Add, remove, and search users
- **Points System**: Track and manage user points
- **Rate Limiting**: IP-based rate limiting (30 requests per 15 seconds)
- **Static File Serving**: Serves HTML/CSS/JS from `www/` directory
- **Database**: SQLite with WAL mode for better concurrency

## Database Schema

### users table
- `uid` (INTEGER PRIMARY KEY)
- `first` (TEXT)
- `last` (TEXT)
- `points` (INTEGER)

### keys table
- `id` (INTEGER PRIMARY KEY)
- `identifier` (TEXT)
- `key_hash` (TEXT)
- `salt` (TEXT)

## Key Differences from C Version

1. **Error Handling**: Go uses explicit error returns instead of return codes
2. **Concurrency**: Built-in mutex-based thread safety instead of pthread
3. **Memory Management**: Automatic garbage collection instead of manual malloc/free
4. **Crypto**: Uses standard library crypto packages
5. **HTTP**: Uses Go's built-in net/http package instead of libmicrohttpd
6. **JSON**: Uses Go's encoding/json package instead of json-c

## Docker Building

## Step 1: Create Dockerfile

```
# Stage 1: Build the Go binary
FROM golang:1.25-alpine AS builder

WORKDIR /build

# Install build dependencies for CGO (sqlite3)
RUN apk add --no-cache build-base

# Copy module files first (better caching)
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source tree
COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY www/ ./www/

# Build the binary
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
    go build -o joepoints ./cmd/joepoints

# Stage 2: Runtime image
FROM alpine:latest

WORKDIR /app

# sqlite3 runtime dependency
RUN apk add --no-cache libc6-compat

# Copy the binary
COPY --from=builder /build/joepoints .

# Copy static assets
COPY --from=builder /build/www ./www

# Expose port
EXPOSE 8080

# Run the app
ENTRYPOINT ["./joepoints"]
CMD ["-port", "8080"]
```

## Step 2: Create .dockerignore File

```
# Git
.git
.gitignore

# Local database files
database/
data.db
data.db-shm
data.db-wal

# Local build artifacts
build/
joepoints
joepoints.exe

# Editor / OS junk
.vscode
.idea
*.swp
*.tmp

# Documentation (not needed in image)
README.md
SECURITY.md

# Mage build artifacts
mage_output_file.go
```

## Step 3: Build the Docker Image

`docker build -t joepoints:latest .`

### Check the image size
`docker images joepoints`

## Step 4: Run the Docker Container

### Default port 8080
docker run -p 8080:8080 joepoints:latest

### Custom internal port
docker run -p 9000:9000 joepoints:latest -port 9000

### With volume for persistent database
docker run -p 8080:8080 -v joepoints-data:/app/database joepoints:latest

### Background mode
docker run -d -p 8080:8080 --name joepoints-server joepoints:latest

## License

This project is licensed under the MIT License. See the LICENSE file for details.