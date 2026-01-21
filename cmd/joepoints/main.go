package main

import (
	"flag"
	"joepoints/internal/db"
	"joepoints/internal/server"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	// Parse command line arguments
	port := flag.Int("port", 8080, "Port to listen on")
	flag.Parse()

	// Setup signal handler for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	slog.Info("Starting server...")

	// Initialize database
	if err := db.DBInit("data.db"); err != nil {
		slog.Error("Failed to initialize database", "error", err)
		os.Exit(1)
	}

	// Start server on specified port
	go func() {
		if err := server.StartServer(*port); err != nil {
			// http.ErrServerClosed is not an error, it's the expected result of graceful shutdown
			if err != http.ErrServerClosed {
				slog.Error("Server error", "error", err)
				os.Exit(1)
			}
		}
	}()

	// Wait for signal
	<-sigChan
	slog.Info("Stopping server...")

	server.StopServer()
	db.DBClose()

	slog.Info("Server stopped.")
}
