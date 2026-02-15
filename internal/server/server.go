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

// Serves a static file with appropriate headers
func serveFile(w http.ResponseWriter, r *http.Request, filePath string, keepWithinWWW bool) {
	// If is a directory, return not found
	osStat, err := os.Stat(filePath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if osStat.IsDir() {
		http.NotFound(w, r)
		return
	}

	// If keepWithinWWW is true, ensure the file path is within the www directory
	if keepWithinWWW {
		// Expand to absolute path
		absPath, err := filepath.Abs(filePath)
		if err != nil {
			http.NotFound(w, r)
			return
		}

		// Get absolute path of www directory
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

	file, err := os.Open(filePath)
	if err != nil {
		http.NotFound(w, r)
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
		contentType = "text/html; charset=utf-8"
	case ".css":
		contentType = "text/css"
	case ".js":
		contentType = "application/javascript"
	default:
		contentType = "application/octet-stream"
	}

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
			filePath = "www/index.html"
		case "/admin":
			filePath = "www/admin.html"
		default:
			// Serve requested file from www directory
			filePath = filepath.Join("www", filepath.Clean(url))
		}

		// Check if file exists and serve it
		if _, err := os.Stat(filePath); err == nil {
			serveFile(w, r, filePath, true)
		} else {
			http.NotFound(w, r)
		}
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
