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
	// Parse command line arguments for listening port, default to 8080
	port := flag.Int("port", 8080, "Port to listen on")
	flag.Parse()

	// Setup CTRL + C signal handler for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	slog.Info("Starting server...")

	// Initialize database
	dbDir := "database"
	if err := os.MkdirAll(dbDir, 0o755); err != nil {
		slog.Error("Failed to create database directory", "error", err)
		os.Exit(1)
	}

	dbPath := dbDir + string(os.PathSeparator) + "data.db"
	if err := db.DBInit(dbPath); err != nil {
		slog.Error("Failed to initialize database", "error", err)
		os.Exit(1)
	}

	// Start server on specified port
	go func() {
		if err := server.StartServer(*port); err != nil {
			// Note: http.ErrServerClosed is a graceful shutdown
			if err != http.ErrServerClosed {
				slog.Error("Server error", "error", err)
				os.Exit(1)
			}
		}
	}()

	// Wait for signal
	<-sigChan
	slog.Info("Stopping server...")

	// Cleanup
	server.StopServer()
	db.DBClose()

	slog.Info("Server stopped.")
}
