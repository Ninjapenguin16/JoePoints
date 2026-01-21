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
