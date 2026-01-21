package server

import (
	"io"
	"joepoints/internal/api"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	MaxConnections    = 100
	ConnectionTimeout = 5 * time.Second
	MaxHeaderSize     = 8192
	MaxBodySizeBytes  = api.MaxBodySize

	MaxRequestsPerIP = 30
	RateLimitWindow  = 15 * time.Second
)

var (
	server  *http.Server
	ipTable map[string]*ipEntry
	ipLock  sync.Mutex
	ticker  *time.Ticker
)

type ipEntry struct {
	count       int
	lastReset   time.Time
	rateLimited bool // Track if we've already logged this IP hitting the limit
}

func init() {
	ipTable = make(map[string]*ipEntry)

	// Start cleanup goroutine to remove stale IP entries every minute
	ticker = time.NewTicker(1 * time.Minute)
	go cleanupIPTable()
}

// cleanupIPTable removes IP entries that haven't been reset in over 1 hour
func cleanupIPTable() {
	for range ticker.C {
		ipLock.Lock()
		now := time.Now()
		for ip, entry := range ipTable {
			if now.Sub(entry.lastReset) > 1*time.Hour {
				delete(ipTable, ip)
			}
		}
		ipLock.Unlock()
	}
}

// checkRateLimit checks if a client is rate limited
// Only logs the first time an IP violates the limit per time window to prevent log spam
// If an IP is already rate limited and sends another request, resets their timer window
func checkRateLimit(r *http.Request) bool {
	ipLock.Lock()
	defer ipLock.Unlock()

	// Get client IP
	ip := getClientIP(r)
	if ip == "" {
		return false
	}

	now := time.Now()
	entry, exists := ipTable[ip]

	if !exists {
		ipTable[ip] = &ipEntry{count: 1, lastReset: now, rateLimited: false}
		return false
	}

	if now.Sub(entry.lastReset) > RateLimitWindow {
		// New window: reset count and timer
		entry.count = 1
		entry.lastReset = now
		entry.rateLimited = false // Reset flag for new window so we log again next window
		return false
	}

	entry.count++
	isLimited := entry.count > MaxRequestsPerIP

	// Only log the first time this IP hits the limit in this window
	if isLimited && !entry.rateLimited {
		entry.rateLimited = true
		slog.Warn("RATE_LIMIT_EXCEEDED",
			"ip", ip,
			"requestCount", entry.count,
			"limit", MaxRequestsPerIP,
		)
	}

	// If already rate limited and they send another request, reset their timer
	// This ensures they can't escape the rate limit without waiting the full window
	if isLimited {
		entry.lastReset = now
	}

	return isLimited
}

// getClientIP extracts the client IP from the request
// Only trusts X-Forwarded-For from direct connection (not from clients)
// In production, configure trusted proxies explicitly
func getClientIP(r *http.Request) string {
	// Only use X-Forwarded-For if behind a reverse proxy (configure accordingly)
	// For now, use the direct RemoteAddr for security
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	return ip
}

// serveFile serves a static file from the www directory
func serveFile(w http.ResponseWriter, filePath string) {
	file, err := os.Open(filePath)
	if err != nil {
		http.NotFound(w, nil)
		return
	}
	defer file.Close()

	// Get file info for content length
	stat, err := file.Stat()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Set content type based on extension
	ext := filepath.Ext(filePath)
	var contentType string
	switch ext {
	case ".html":
		contentType = "text/html"
	case ".css":
		contentType = "text/css"
	case ".js":
		contentType = "application/javascript"
	default:
		contentType = "application/octet-stream"
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Length", strconv.FormatInt(stat.Size(), 10))
	w.WriteHeader(http.StatusOK)

	io.Copy(w, file)
}

// requestHandler handles incoming HTTP requests
func requestHandler(w http.ResponseWriter, r *http.Request) {
	// Check rate limiting
	if checkRateLimit(r) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"error":"Too Many Requests"}`))
		return
	}

	// Enforce max body size
	r.Body = http.MaxBytesReader(w, r.Body, int64(MaxBodySizeBytes))

	url := r.URL.Path

	// Serve static files if not an API request
	if !strings.HasPrefix(url, "/api/") {
		var filePath string

		// Root path defaults to index.html
		if url == "/" {
			filePath = "www/index.html"
		} else if url == "/cli" {
			filePath = "www/cli.html"
		} else {
			// Serve requested file from www directory with security check
			filePath = filepath.Join("www", filepath.Clean(url))

			// Prevent directory traversal attacks
			// Ensure the resolved path is still within www directory
			absPath, err := filepath.Abs(filePath)
			if err != nil {
				http.NotFound(w, r)
				return
			}

			wwwAbs, err := filepath.Abs("www")
			if err != nil {
				http.NotFound(w, r)
				return
			}

			// Check if the path is within www directory
			if !strings.HasPrefix(absPath, wwwAbs+string(filepath.Separator)) && absPath != wwwAbs {
				http.NotFound(w, r)
				return
			}
		}

		// Check if file exists
		if _, err := os.Stat(filePath); err == nil {
			serveFile(w, filePath)
		} else {
			http.NotFound(w, r)
		}
		return
	}

	// Handle API requests
	api.APIDispatcher(w, r)
}

// StartServer starts the HTTP server on the specified port
func StartServer(port int) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", requestHandler)

	server = &http.Server{
		Addr:           ":" + strconv.Itoa(port),
		Handler:        mux,
		ReadTimeout:    ConnectionTimeout,
		WriteTimeout:   ConnectionTimeout,
		IdleTimeout:    ConnectionTimeout,
		MaxHeaderBytes: MaxHeaderSize,
	}

	slog.Info("Server listening", "port", port)

	return server.ListenAndServe()
}

// StopServer stops the HTTP server gracefully
func StopServer() {
	if server != nil {
		server.Close()
		server = nil
	}
	if ticker != nil {
		ticker.Stop()
	}
}
