package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// Max concurrent hashes
const maxHashRoutines = 16

var hashSem = make(chan struct{}, maxHashRoutines)

// Derives a key using Argon2id.
func Argon2idKey(password, salt []byte, keyLen uint32, timeCost uint32, memoryKB uint32, threads uint8) ([]byte, error) {
	if len(password) == 0 || len(salt) == 0 || timeCost == 0 || memoryKB == 0 || threads == 0 {
		return nil, fmt.Errorf("invalid parameters")
	}

	hashSem <- struct{}{}
	defer func() { <-hashSem }()

	key := argon2.IDKey(
		password,
		salt,
		timeCost,
		memoryKB,
		threads,
		keyLen,
	)

	return key, nil
}

//
// ===== Encoding helpers =====
//

func HexEncode(data []byte) string {
	return hex.EncodeToString(data)
}

func HexDecode(hexStr string) ([]byte, error) {
	return hex.DecodeString(hexStr)
}

//
// ===== Random helpers =====
//

func GenerateSaltBytes(length int) ([]byte, error) {
	salt := make([]byte, length)

	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}

	return salt, nil
}

// Generates 128-bit random API key (32 hex chars)
func GenerateRandomKey() (string, error) {
	bytes := make([]byte, 16)

	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	return HexEncode(bytes), nil
}
