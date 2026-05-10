package application

import (
	"crypto/sha256"
	"crypto/subtle"
)

// ConstantTimeSecretEqual compares two non-empty secrets without exposing early
// byte differences through normal string comparison timing.
func ConstantTimeSecretEqual(provided, expected string) bool {
	if provided == "" || expected == "" {
		return false
	}
	providedHash := sha256.Sum256([]byte(provided))
	expectedHash := sha256.Sum256([]byte(expected))
	return subtle.ConstantTimeCompare(providedHash[:], expectedHash[:]) == 1
}
