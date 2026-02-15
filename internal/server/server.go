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
	MaxConnections     = 100
	ConnectionTimeout  = 5 * time.Second
	MaxHeaderSize      = 8192
	MaxBodySizeBytes   = api.MaxBodySize
	MaxRequestsPerIP   = 30
	RateLimitWindow    = 15 * time.Second
	WhitelistLocalhost = true
)

var (
	server  *http.Server
	ipTable map[string]*ipEntry
	ipLock  sync.Mutex
	ticker  *time.Ticker
)

// IP rate limiting entry
type ipEntry struct {
	count       int
	lastReset   time.Time
	rateLimited bool
}

// Initialize IP table and start cleanup goroutine
func init() {
	ipTable = make(map[string]*ipEntry)

	// Start cleanup goroutine to remove stale IP entries every minute
	ticker = time.NewTicker(1 * time.Minute)
	go cleanupIPTable()
}

// Removes IP entries that haven't been reset in over 1 hour
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

// Checks if a client is rate limited
// Only logs the first time an IP violates the limit per time window to prevent log spam
// If an IP is already rate limited and sends another request, resets their timer window
func checkRateLimit(r *http.Request) bool {
	ipLock.Lock()
	defer ipLock.Unlock()

	// Get client IP
	ip := GetClientIP(r)
	if ip == "" {
		return false
	}
	if WhitelistLocalhost && (ip == "127.0.0.1" || ip == "::1") {
		return false
	}

	now := time.Now()
	entry, exists := ipTable[ip]

	if !exists {
		ipTable[ip] = &ipEntry{count: 1, lastReset: now, rateLimited: false}
		return false
	}

	if now.Sub(entry.lastReset) > RateLimitWindow {
		// New window, reset count and timer
		entry.count = 1
		entry.lastReset = now
		entry.rateLimited = false
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
	if isLimited {
		entry.lastReset = now
	}

	return isLimited
}

// Extracts the client IP from the request
func GetClientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	return ip
}

// Vets the user-provided path first before serving a static file with appropriate headers
// Resolves symlinks before checks and serving
func serveFile(w http.ResponseWriter, r *http.Request, userPath string, keepWithinWWW bool) {
	var finalPath string

	if keepWithinWWW {
		// Absolute path to www root
		wwwRoot, err := filepath.Abs("www")
		if err != nil {
			http.NotFound(w, r)
			return
		}

		// Normalize user path by removing leading slash
		cleanPath := strings.TrimPrefix(userPath, "/")

		// Join user path with www root
		requestedPath := filepath.Join(wwwRoot, cleanPath)

		// Resolve symlinks
		realPath, err := filepath.EvalSymlinks(requestedPath)
		if err != nil {
			http.NotFound(w, r)
			return
		}

		// Ensure resolved path is still inside www
		rel, err := filepath.Rel(wwwRoot, realPath)
		if err != nil || strings.HasPrefix(rel, "..") {
			http.NotFound(w, r)
			return
		}

		finalPath = realPath
	} else {
		// Not constrained to www
		absPath, err := filepath.Abs(userPath)
		if err != nil {
			http.NotFound(w, r)
			return
		}

		realPath, err := filepath.EvalSymlinks(absPath)
		if err != nil {
			http.NotFound(w, r)
			return
		}

		finalPath = realPath
	}

	// Check if file exists and is not a directory
	stat, err := os.Stat(finalPath)
	if err != nil || stat.IsDir() {
		http.NotFound(w, r)
		return
	}

	// Open file
	file, err := os.Open(finalPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer file.Close()

	// Detect content type by extension
	ext := filepath.Ext(finalPath)
	var contentType string
	switch ext {
	case ".html":
		contentType = "text/html; charset=utf-8"
	case ".css":
		contentType = "text/css"
	case ".js":
		contentType = "application/javascript"
	default:
		contentType = "application/octet-stream"
	}

	// Set security headers and write file
	api.SetSecurityHeaders(w)
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", strconv.FormatInt(stat.Size(), 10))
	w.WriteHeader(http.StatusOK)

	io.Copy(w, file)
}

// Handles incoming HTTP requests
func requestHandler(w http.ResponseWriter, r *http.Request) {
	// Check rate limiting
	if checkRateLimit(r) {
		api.SetSecurityHeaders(w)
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
		switch url {
		case "/":
			filePath = "index.html"
		case "/admin":
			filePath = "admin.html"
		default:
			filePath = url
		}

		// Will clean and ensure the path is within the www directory, otherwise will return 404
		serveFile(w, r, filePath, true)

		return
	}

	// Handle API requests
	api.APIDispatcher(w, r)
}

// Starts the HTTP server on the specified port
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

// Stops the HTTP server gracefully
func StopServer() {
	if server != nil {
		server.Close()
		server = nil
	}
	if ticker != nil {
		ticker.Stop()
	}
}
