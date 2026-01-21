# JoePoints - Go Version

This is a Golang conversion of the JoePoints application, a points/rewards system with API authentication, user management, and SQLite database storage.

## Project Structure

- `main.go` - Application entry point with signal handling and server startup
- `crypto.go` - Cryptographic functions (PBKDF2-HMAC-SHA256, hex encoding/decoding)
- `db.go` - SQLite database operations and user management
- `api.go` - HTTP API endpoint handlers and request validation
- `server.go` - HTTP server setup and rate limiting
- `go.mod` - Go module dependencies

## Dependencies

- `github.com/mattn/go-sqlite3` - SQLite3 driver for Go
- `github.com/urfave/negroni` - HTTP middleware (optional, can be removed)

## Building

1. Install Go 1.21 or later
2. Navigate to the GoVer directory
3. Install dependencies:
   ```bash
   go mod download
   ```
4. Build the application:
   ```bash
   go build -o joepoints
   ```

## Running

```bash
./joepoints
```

The server will start on port 8080 and create a SQLite database file at `data.db`.

## API Endpoints

### Authentication
All API endpoints (except listed exceptions) require an `Authorization: Bearer <key>` header.

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
- **CORS Support**: Full CORS headers on all responses
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

# Copy go.mod and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY *.go ./

# Build the binary (statically linked)
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -o joepoints .

# Stage 2: Create minimal runtime image
FROM alpine:latest

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /build/joepoints .

# Copy static files
COPY www/ ./www/

# Expose default port (can be overridden)
EXPOSE 8080

# Run the application
ENTRYPOINT ["./joepoints"]
CMD ["-port", "8080"]
```

## Step 2: Create .dockerignore File

```
data.db
data.db-shm
data.db-wal
joepoints.exe
.git
.gitignore
README.md
```

## Step 3: Build the Docker Image

cd C:\Users\rylan\Desktop\JoePoints\GoVer

### Build the image
docker build -t joepoints:latest .

### Check the image size
docker images joepoints

## Step 4: Run the Docker Container

### Default port 8080
docker run -p 8080:8080 joepoints:latest

### Docker Building
docker run -p 9000:9000 joepoints:latest -port 9000

### With volume for persistent database
docker run -p 8080:8080 -v joepoints-data:/app joepoints:latest

### Background mode
docker run -d -p 8080:8080 --name joepoints-server joepoints:latest

## License

Same as the original C version.
