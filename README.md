# JoePoints v3.0.1 - Go Version

A modern, security-hardened points/rewards system written in Go. Features API authentication with hashed keys, user management, and SQLite database storage with web-based admin panel and public leaderboard.

## Project Structure

joepoints/<br>
├── cmd/joepoints/main.go       # Entry point (package main)<br>
├── internal/<br>
│   ├── api/api.go              # HTTP API handlers & security<br>
│   ├── server/server.go        # Server setup and request handling<br>
│   ├── db/db.go                # SQLite database operations<br>
│   └── crypto/crypto.go        # Cryptographic functions (Argon2ID)<br>
├── www/                        # Static assets (admin panel, leaderboard)<br>
│   ├── admin.html/css/js       # Web-based admin panel<br>
│   ├── index.html/css/js       # Public leaderboard<br>
│   └── assets/                 # Images and resources<br>
├── Dockerfile                  # Docker image definition<br>
├── .dockerignore               # Docker build exclusions<br>
├── go.mod, go.sum              # Go module definitions<br>
├── mage.go                     # Build automation (Mage)<br>
├── APIDocs.md                  # API documentation<br>
├── README.md, LICENSE<br>
└── .gitignore


## Dependencies

- `modernc.org/sqlite` - Pure Go SQLite3 driver (no CGO required)
- Standard Go library for HTTP, crypto, and JSON handling

## Building

### Using Mage (Recommended)

1. Install Go 1.26.0 or later
2. Navigate to the project root
3. Install Mage: `go install github.com/magefile/mage@latest`
4. Build:
   ```bash
   mage build           # Standard binary for current OS/Arch
   mage all             # Build for all supported platforms
   mage release x.x.x   # Release builds with www/ folder (requires version string)
   mage clean           # Remove build artifacts
   ```

### Using Go directly

1. Install Go 1.26 or later
2. Navigate to the project root
3. Install dependencies:
   ```bash
   go mod download
   ```
4. Build the application:
   ```bash
   go build -o build/joepoints ./cmd/joepoints
   ```

## Running

```bash
./joepoints [-port <port_number>]
```

By default the server will:
* Listen on port 8080
* Use `database/data.db` for the SQLite database
* Serve static files from `www/` directory

## Security Recommendations

**First Run**: On first run, a default API key with identifier 'firstrun' is created automatically. For security:
* **Create a new API key** using the admin panel or API
* **Delete the 'firstrun' key** immediately after creating your own key
* Never use the default key in production environments

## API Endpoints

All endpoints accept `POST` requests with JSON bodies and return JSON responses.

### Authentication
Write operations require an `Authorization: Bearer <key>` header with a valid API key.
Read operations do not require authentication.

### Endpoints

**Write Operations** (require authentication):
- `POST /api/genkey` - Generate a new API key
- `POST /api/addperson` - Add a new user
- `POST /api/removeperson` - Remove a user
- `POST /api/setpoints` - Set user's points
- `POST /api/addpoints` - Add/subtract points from user
- `POST /api/removekey` - Revoke current API key
- `POST /api/getidentifier` - Get identifier for current API key

**Read Operations** (no authentication required):
- `POST /api/getuid` - Get user ID by name
- `POST /api/getpoints` - Get user's points
- `POST /api/getall` - Get all users (leaderboard data)

For detailed API documentation, see [APIDocs.md](APIDocs.md).

## Features

- **Security Hardened**:
  - API keys hashed with Argon2ID (memory-hard hashing)
  - Strong Content Security Policy (CSP) on all pages
  - Security headers: X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy
  - No inline scripts or styles (CSP compliant)
  - CORS removed entirely

- **User Management**:
  - Add, remove, and search users by name
  - Auto-assigned unique UIDs
  - Points tracking and manipulation
  - Prevents duplicate users

- **Points System**:
  - Set points to exact value
  - Add/subtract points with overflow protection
  - 32-bit signed integer range (-2.1B to +2.1B)
  - Transaction-safe operations

- **API Key Management**:
  - Generate keys with custom identifiers
  - Immediate Argon2ID hashing on receipt
  - Raw keys zeroed in memory after hashing
  - Revocable at any time
  - Key identifier lookup

- **Web Interfaces**:
  - Admin panel for managing users and points
  - Public leaderboard view
  - Responsive design
  - No framework dependencies (plain CSS/JS)

- **Database**: SQLite with proper concurrency handling
- **No CGO**: Uses pure Go SQLite driver for easier deployment

## Database Schema

**Note**: Databases from v2.0 are no longer compatible with v3.0. Use a fresh database or migrate manually.

### keys table
```sql
CREATE TABLE keys (
  id INTEGER PRIMARY KEY,
  identifier TEXT,
  key_hash TEXT,
  salt TEXT,
  argon2_time_cost INTEGER,
  argon2_memory_kb INTEGER,
  argon2_threads INTEGER
)
```

### users table
```sql
CREATE TABLE users (
  uid INTEGER PRIMARY KEY,
  first TEXT,
  last TEXT,
  points INTEGER DEFAULT 0
)
```

## Docker

A Dockerfile is included in the project root. The image:
- Uses multi-stage build for minimal size (~6MB)
- Requires no CGO (uses pure Go SQLite)
- Includes web assets (`www/` folder)

### Building the Docker image

```bash
docker build -t joepoints:latest .
```

### Running the container

```bash
# Default port 8080
docker run -p 8080:8080 joepoints:latest

# Custom internal port
docker run -p 9000:9000 joepoints:latest -port 9000

# Persistent database volume
docker run -p 8080:8080 -v joepoints-data:/app/database joepoints:latest

# Background mode
docker run -d -p 8080:8080 --name joepoints-server joepoints:latest
```

### Image details
- **Base**: Alpine Linux (minimal)
- **Build image**: golang:1.26-alpine (discarded after build)
- **Runtime**: Pure Go binary, no CGO dependencies
- **Size**: ~6MB (optimized)
- **Exposed port**: 8080 (configurable via `-port` flag)

## Possible Future Features (v4.0)

- **OAuth2 Authentication**: Switch to OAuth2 for user authentication while maintaining current ID and API key system for session management
- **gRPC Protocol**: Migrate from JSON-RPC to gRPC for improved performance and type safety

## License

This project is licensed under the MIT License. See the LICENSE file for details.
