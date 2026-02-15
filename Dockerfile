# ---------- Stage 1: Build ----------
FROM golang:1.26-alpine AS builder

WORKDIR /build
ENV CGO_ENABLED=0

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY www/ ./www/

RUN GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" \
    -o joepoints ./cmd/joepoints


# ---------- Stage 2: Runtime ----------
FROM alpine:latest

WORKDIR /app

# Copy binary
COPY --from=builder /build/joepoints .

# Copy static files
COPY --from=builder /build/www ./www

# Make www read-only
RUN chmod -R 0555 /app/www

# Create writable database directory
RUN mkdir -p /app/database

# Mark database as persistent volume
VOLUME ["/app/database"]

EXPOSE 8080

ENTRYPOINT ["./joepoints"]
CMD ["-port", "8080"]
