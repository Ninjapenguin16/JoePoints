package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"joepoints/internal/crypto"
	"log/slog"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var (
	db     *sql.DB
	dbLock sync.RWMutex
)

const (
	pbkdf2Iterations = 100000
	saltSize         = 16
	hashSize         = 32
)

// DBInit initializes the database and creates tables
func DBInit(path string) error {
	var err error
	db, err = sql.Open("sqlite3", path)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

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
			salt TEXT
		)
	`); err != nil {
		return err
	}

	// Check if we need to migrate from legacy schema
	rows, err := db.Query("PRAGMA table_info(keys)")
	if err != nil {
		return err
	}
	defer rows.Close()

	hasKey := false
	hasHash := false
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype string
		var dfltValue interface{}
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err != nil {
			return err
		}
		if name == "key" {
			hasKey = true
		}
		if name == "key_hash" {
			hasHash = true
		}
	}

	// Migrate from legacy schema if needed
	if hasKey && !hasHash {
		if err := migrateKeys(); err != nil {
			return err
		}
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

// migrateKeys migrates from legacy plaintext key storage to hashed storage
func migrateKeys() error {
	dbLock.Lock()
	defer dbLock.Unlock()

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Create new keys table
	if _, err := tx.Exec(`
		CREATE TABLE IF NOT EXISTS keys_new (
			id INTEGER PRIMARY KEY,
			identifier TEXT,
			key_hash TEXT,
			salt TEXT
		)
	`); err != nil {
		return err
	}

	// Migrate existing keys
	rows, err := tx.Query("SELECT key FROM keys")
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var oldKey string
		if err := rows.Scan(&oldKey); err != nil {
			return err
		}

		saltRaw, err := crypto.GenerateSaltBytes(saltSize)
		if err != nil {
			return err
		}

		hash, err := crypto.PBKDF2HMACSHA256([]byte(oldKey), saltRaw, pbkdf2Iterations, hashSize)
		if err != nil {
			return err
		}

		if _, err := tx.Exec(
			"INSERT INTO keys_new (identifier, key_hash, salt) VALUES (?, ?, ?)",
			"FirstRun", crypto.HexEncode(hash), crypto.HexEncode(saltRaw),
		); err != nil {
			return err
		}
	}

	if _, err := tx.Exec("DROP TABLE keys"); err != nil {
		return err
	}

	if _, err := tx.Exec("ALTER TABLE keys_new RENAME TO keys"); err != nil {
		return err
	}

	return tx.Commit()
}

// DBClose closes the database connection
func DBClose() {
	if db != nil {
		db.Close()
	}
}

// DBCreateKey creates a new API key and stores it hashed in the database
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
	hash, err := crypto.PBKDF2HMACSHA256([]byte(key), saltRaw, pbkdf2Iterations, hashSize)
	if err != nil {
		return "", err
	}

	// Insert into database
	_, err = db.Exec(
		"INSERT INTO keys (identifier, key_hash, salt) VALUES (?, ?, ?)",
		identifier, crypto.HexEncode(hash), crypto.HexEncode(saltRaw),
	)
	if err != nil {
		return "", err
	}

	return key, nil
}

// DBAuthKeyExists checks if an API key is valid
func DBAuthKeyExists(key string) bool {
	dbLock.RLock()
	defer dbLock.RUnlock()

	if db == nil {
		return false
	}

	rows, err := db.Query("SELECT key_hash, salt FROM keys")
	if err != nil {
		return false
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

		hash, err := crypto.PBKDF2HMACSHA256([]byte(key), saltRaw, pbkdf2Iterations, hashSize)
		if err != nil {
			continue
		}

		if crypto.HexEncode(hash) == keyHashHex {
			return true
		}
	}

	return false
}

// DBAddUser adds a new user to the database
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

// DBRemoveUser removes a user from the database
func DBRemoveUser(uid int) error {
	dbLock.Lock()
	defer dbLock.Unlock()

	if db == nil {
		return fmt.Errorf("database not initialized")
	}

	_, err := db.Exec("DELETE FROM users WHERE uid=?", uid)
	return err
}

// DBGetUIDByName returns UIDs for users matching first and last name
func DBGetUIDByName(first, last string) ([]int, error) {
	dbLock.RLock()
	defer dbLock.RUnlock()

	if db == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	rows, err := db.Query("SELECT uid FROM users WHERE first=? AND last=?", first, last)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var uids []int
	for rows.Next() {
		var uid int
		if err := rows.Scan(&uid); err != nil {
			return nil, err
		}
		uids = append(uids, uid)
	}

	if len(uids) == 0 {
		return nil, fmt.Errorf("no matches found")
	}

	return uids, nil
}

// DBGetPoints returns the points for a user
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

// DBSetPoints sets the points for a user
func DBSetPoints(uid, points int) error {
	dbLock.Lock()
	defer dbLock.Unlock()

	if db == nil {
		return fmt.Errorf("database not initialized")
	}

	_, err := db.Exec("UPDATE users SET points=? WHERE uid=?", points, uid)
	return err
}

// DBAddPoints adds points to a user's total
func DBAddPoints(uid, delta int) error {
	dbLock.Lock()
	defer dbLock.Unlock()

	if db == nil {
		return fmt.Errorf("database not initialized")
	}

	_, err := db.Exec("UPDATE users SET points=points+? WHERE uid=?", delta, uid)
	return err
}

// User represents a user record
type User struct {
	UID    int    `json:"uid"`
	First  string `json:"first"`
	Last   string `json:"last"`
	Points int    `json:"points"`
}

// DBGetAllUsers returns all users as JSON
func DBGetAllUsers() (string, error) {
	dbLock.RLock()
	defer dbLock.RUnlock()

	if db == nil {
		return "[]", fmt.Errorf("database not initialized")
	}

	rows, err := db.Query("SELECT uid, first, last, points FROM users")
	if err != nil {
		return "[]", err
	}
	defer rows.Close()

	users := make([]User, 0)
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.UID, &user.First, &user.Last, &user.Points); err != nil {
			return "[]", err
		}
		users = append(users, user)
	}

	data, err := json.Marshal(users)
	if err != nil {
		return "[]", err
	}

	return string(data), nil
}

// DBRemoveKey removes an API key by its cleartext value
func DBRemoveKey(key string) error {
	dbLock.Lock()
	defer dbLock.Unlock()

	if db == nil {
		return fmt.Errorf("database not initialized")
	}

	// Find the key ID by matching hash
	rows, err := db.Query("SELECT id, key_hash, salt FROM keys")
	if err != nil {
		return err
	}
	defer rows.Close()

	var foundID int = -1
	for rows.Next() {
		var id int
		var keyHashHex, saltHex string
		if err := rows.Scan(&id, &keyHashHex, &saltHex); err != nil {
			continue
		}

		saltRaw, err := crypto.HexDecode(saltHex)
		if err != nil {
			continue
		}

		hash, err := crypto.PBKDF2HMACSHA256([]byte(key), saltRaw, pbkdf2Iterations, hashSize)
		if err != nil {
			continue
		}

		if crypto.HexEncode(hash) == keyHashHex {
			foundID = id
			break
		}
	}

	if foundID < 0 {
		return fmt.Errorf("key not found")
	}

	_, err = db.Exec("DELETE FROM keys WHERE id=?", foundID)
	return err
}
