package db

import (
	"database/sql"
	"fmt"
	"joepoints/internal/crypto"
	"log/slog"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

var (
	db     *sql.DB
	dbLock sync.RWMutex
)

const (
	// Must both be multiples of 2
	saltSize = 16
	hashSize = 32

	// Hash configuration
	argon2TimeCost = 1
	argon2MemoryKB = 16 * 1024 // 16 MB
	argon2Threads  = 1

	// Database connectons configuration
	dbMaxConnections        = 25
	dbMaxIdelConnections    = 5
	dbConnectionMaxLifetime = 5 * time.Minute
)

// Compile time check that hashSize and saltSize are multiples of 2
var _ [-(hashSize % 2)]int
var _ [-(saltSize % 2)]int

// Initializes the database and creates tables
func DBInit(path string) error {
	var err error
	db, err = sql.Open("sqlite", path)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(dbMaxConnections)
	db.SetMaxIdleConns(dbMaxIdelConnections)
	db.SetConnMaxLifetime(dbConnectionMaxLifetime)

	// Enable WAL mode for better concurrency
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return err
	}

	// Create users table
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			uid INTEGER PRIMARY KEY,
			first TEXT,
			last TEXT,
			points INTEGER DEFAULT 0
		)
	`); err != nil {
		return err
	}

	// Create keys table
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS keys (
			id INTEGER PRIMARY KEY,
			identifier TEXT,
			key_hash TEXT,
			salt TEXT,
			argon2_time_cost INTEGER,
			argon2_memory_kb INTEGER,
			argon2_threads INTEGER
		)
	`); err != nil {
		return err
	}

	// Generate initial key if none exist
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM keys").Scan(&count); err != nil {
		return err
	}

	if count == 0 {
		key, err := DBCreateKey("FirstRun")
		if err != nil {
			return err
		}
		slog.Info("Initial API Key", "key", key)
	}

	return nil
}

// Closes the database connection
func DBClose() {
	if db != nil {
		db.Close()
	}
}

// Creates a new API key and stores its hashed in the database
func DBCreateKey(identifier string) (string, error) {
	dbLock.Lock()
	defer dbLock.Unlock()

	if db == nil {
		return "", fmt.Errorf("database not initialized")
	}

	// Generate cleartext key
	key, err := crypto.GenerateRandomKey()
	if err != nil {
		return "", err
	}

	// Generate salt
	saltRaw, err := crypto.GenerateSaltBytes(saltSize)
	if err != nil {
		return "", err
	}

	// Hash the key
	hash, err := crypto.Argon2idKey([]byte(key), saltRaw, hashSize, argon2TimeCost, argon2MemoryKB, argon2Threads)
	if err != nil {
		return "", err
	}

	// Find the lowest unused ID
	var newID int
	err = db.QueryRow(`
		SELECT COALESCE(MIN(t1.id + 1), 1)
		FROM keys t1
		LEFT JOIN keys t2 ON t1.id + 1 = t2.id
		WHERE t2.id IS NULL
	`).Scan(&newID)
	if err != nil {
		return "", fmt.Errorf("failed to find unused ID: %w", err)
	}

	// Insert into database
	_, err = db.Exec(
		"INSERT INTO keys (id, identifier, key_hash, salt, argon2_time_cost, argon2_memory_kb, argon2_threads) VALUES (?, ?, ?, ?, ?, ?, ?)",
		newID, identifier, crypto.HexEncode(hash), crypto.HexEncode(saltRaw), argon2TimeCost, argon2MemoryKB, argon2Threads,
	)
	if err != nil {
		return "", err
	}

	return key, nil
}

// Checks if an API key is valid
func DBAuthKeyExists(key string) (bool, string) {
	dbLock.RLock()
	defer dbLock.RUnlock()

	if db == nil {
		return false, ""
	}

	rows, err := db.Query("SELECT key_hash, salt FROM keys")
	if err != nil {
		return false, ""
	}
	defer rows.Close()

	for rows.Next() {
		var keyHashHex, saltHex string
		if err := rows.Scan(&keyHashHex, &saltHex); err != nil {
			continue
		}

		saltRaw, err := crypto.HexDecode(saltHex)
		if err != nil {
			continue
		}

		var timeCost, memoryKB uint32
		var threads uint8
		if err := db.QueryRow("SELECT argon2_time_cost, argon2_memory_kb, argon2_threads FROM keys WHERE key_hash=?", keyHashHex).Scan(&timeCost, &memoryKB, &threads); err != nil {
			continue
		}

		hash, err := crypto.Argon2idKey([]byte(key), saltRaw, uint32(len(keyHashHex)/2), timeCost, memoryKB, threads)
		if err != nil {
			slog.Error("Key entry with invalid argon2 params", "error", err)
			continue
		}

		if crypto.HexEncode(hash) == keyHashHex {
			return true, keyHashHex
		}
	}

	return false, ""
}

// Returns the identifier of a key given its hash
func DBGetKeyIdentifier(keyHash string) (string, error) {
	dbLock.RLock()
	defer dbLock.RUnlock()

	if db == nil {
		return "", fmt.Errorf("database not initialized")
	}

	var identifier string
	if err := db.QueryRow("SELECT identifier FROM keys WHERE key_hash = ?", keyHash).Scan(&identifier); err != nil {
		return "", err
	}

	return identifier, nil
}

// Adds a new user to the database
func DBAddUser(first, last string) (int, error) {
	dbLock.Lock()
	defer dbLock.Unlock()

	if db == nil {
		return 0, fmt.Errorf("database not initialized")
	}

	// Check for duplicates
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM users WHERE first=? AND last=?", first, last).Scan(&count); err != nil {
		return 0, err
	}
	if count > 0 {
		return 0, fmt.Errorf("user already exists")
	}

	// Find next available UID
	var uid int
	if err := db.QueryRow(`
		SELECT COALESCE(MIN(t1.uid + 1), 1)
		FROM users t1
		LEFT JOIN users t2 ON t1.uid + 1 = t2.uid
		WHERE t2.uid IS NULL
	`).Scan(&uid); err != nil {
		return 0, err
	}

	// Insert user
	if _, err := db.Exec("INSERT INTO users (uid, first, last, points) VALUES (?, ?, ?, 0)", uid, first, last); err != nil {
		return 0, err
	}

	return uid, nil
}

// Removes a user from the database
func DBRemoveUser(uid int) error {
	dbLock.Lock()
	defer dbLock.Unlock()

	if db == nil {
		return fmt.Errorf("database not initialized")
	}

	_, err := db.Exec("DELETE FROM users WHERE uid=?", uid)
	return err
}

// Returns UID for the user matching first and last name
func DBGetUIDByName(first, last string) (int, error) {
	dbLock.RLock()
	defer dbLock.RUnlock()

	if db == nil {
		return 0, fmt.Errorf("database not initialized")
	}

	rows, err := db.Query("SELECT uid FROM users WHERE first=? AND last=?", first, last)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	var uids []int
	for rows.Next() {
		var uid int
		if err := rows.Scan(&uid); err != nil {
			return 0, err
		}
		uids = append(uids, uid)
	}

	if len(uids) == 0 {
		return 0, fmt.Errorf("no matches found")
	}

	return uids[0], nil
}

// Returns the points for a user
func DBGetPoints(uid int) (int, error) {
	dbLock.RLock()
	defer dbLock.RUnlock()

	if db == nil {
		return 0, fmt.Errorf("database not initialized")
	}

	var points int
	if err := db.QueryRow("SELECT points FROM users WHERE uid=?", uid).Scan(&points); err != nil {
		if err == sql.ErrNoRows {
			return 0, fmt.Errorf("user not found")
		}
		return 0, err
	}

	return points, nil
}

// Sets the points for a user
func DBSetPoints(uid, points int) error {
	dbLock.Lock()
	defer dbLock.Unlock()

	if db == nil {
		return fmt.Errorf("database not initialized")
	}

	_, err := db.Exec("UPDATE users SET points=? WHERE uid=?", points, uid)
	return err
}

// Adds points to a user's total
func DBAddPoints(uid, points int) error {
	dbLock.Lock()
	defer dbLock.Unlock()

	if db == nil {
		return fmt.Errorf("database not initialized")
	}

	_, err := db.Exec("UPDATE users SET points=points+? WHERE uid=?", points, uid)
	return err
}

// User record
type User struct {
	UID    int    `json:"uid"`
	First  string `json:"first"`
	Last   string `json:"last"`
	Points int    `json:"points"`
}

// Returns all users as JSON
func DBGetAllUsers() ([]User, error) {
	dbLock.RLock()
	defer dbLock.RUnlock()

	if db == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	rows, err := db.Query("SELECT uid, first, last, points FROM users")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	users := make([]User, 0)

	for rows.Next() {
		var user User
		if err := rows.Scan(&user.UID, &user.First, &user.Last, &user.Points); err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	return users, nil
}

// Removes an API key by its hashed value
// Use DBAuthKeyExists to get the hash of the key to remove
func DBRemoveKey(keyHash string) error {
	dbLock.Lock()
	defer dbLock.Unlock()

	if db == nil {
		return fmt.Errorf("database not initialized")
	}

	result, err := db.Exec(
		"DELETE FROM keys WHERE key_hash = ?",
		keyHash,
	)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rows == 0 {
		return fmt.Errorf("key not found")
	}

	return nil
}
