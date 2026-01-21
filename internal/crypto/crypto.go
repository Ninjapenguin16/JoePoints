package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// PBKDF2HMACSHA256 derives a key from a password using PBKDF2-HMAC-SHA256
func PBKDF2HMACSHA256(password, salt []byte, iterations, outputLen int) ([]byte, error) {
	if len(password) == 0 || len(salt) == 0 || iterations <= 0 || outputLen <= 0 {
		return nil, fmt.Errorf("invalid parameters")
	}

	hashLen := sha256.Size
	blocks := (outputLen + hashLen - 1) / hashLen

	output := make([]byte, outputLen)

	for block := 1; block <= blocks; block++ {
		// Create salt || INT(block) in big-endian
		blockSalt := append(salt, byte((block>>24)&0xff), byte((block>>16)&0xff), byte((block>>8)&0xff), byte(block&0xff))

		// First iteration: U1 = HMAC(password, salt || INT(block))
		h := hmac.New(sha256.New, password)
		h.Write(blockSalt)
		U := h.Sum(nil)
		T := make([]byte, len(U))
		copy(T, U)

		// Remaining iterations
		for i := 1; i < iterations; i++ {
			h = hmac.New(sha256.New, password)
			h.Write(U)
			U = h.Sum(nil)

			for j := 0; j < len(U); j++ {
				T[j] ^= U[j]
			}
		}

		// Copy to output
		offset := (block - 1) * hashLen
		copyLen := hashLen
		if offset+copyLen > outputLen {
			copyLen = outputLen - offset
		}
		copy(output[offset:offset+copyLen], T[:copyLen])
	}

	return output, nil
}

// HexEncode converts bytes to hex string
func HexEncode(data []byte) string {
	return hex.EncodeToString(data)
}

// HexDecode converts hex string to bytes
func HexDecode(hexStr string) ([]byte, error) {
	return hex.DecodeString(hexStr)
}

// GenerateSaltBytes generates random salt bytes
func GenerateSaltBytes(length int) ([]byte, error) {
	salt := make([]byte, length)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

// GenerateRandomKey generates a 32-character hex key
func GenerateRandomKey() (string, error) {
	bytes := make([]byte, 16)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return HexEncode(bytes), nil
}
