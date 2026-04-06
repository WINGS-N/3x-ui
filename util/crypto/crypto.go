// Package crypto provides cryptographic utilities for password hashing and verification.
package crypto

import (
	"crypto/sha256"
	"encoding/hex"

	"golang.org/x/crypto/bcrypt"
)

// HashPasswordAsBcrypt generates a bcrypt hash of the given password.
func HashPasswordAsBcrypt(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash), err
}

// CheckPasswordHash verifies if the given password matches the bcrypt hash.
func CheckPasswordHash(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// HashTokenSHA256 returns a deterministic hash for random API tokens so the plain token
// does not need to be stored in the database.
func HashTokenSHA256(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
