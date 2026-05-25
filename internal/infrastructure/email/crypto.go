package email

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// SecretCrypto encrypts/decrypts client-supplied email provider API keys
// using AES-256-GCM with a master key supplied at process start.
//
// Ciphertext format: GCM AEAD output; the nonce is stored separately so it
// can be queried/rotated without parsing the ciphertext. This matches the
// schema's (api_key_ciphertext, api_key_nonce) split.
type SecretCrypto struct {
	aead cipher.AEAD
}

// NewSecretCrypto parses a base64-encoded 32-byte master key. The key
// should come from the EMAIL_CONFIG_KMS_KEY env var.
func NewSecretCrypto(masterKeyB64 string) (*SecretCrypto, error) {
	if masterKeyB64 == "" {
		return nil, errors.New("email crypto: master key not configured")
	}
	keyBytes, err := base64.StdEncoding.DecodeString(masterKeyB64)
	if err != nil {
		return nil, fmt.Errorf("email crypto: decode master key: %w", err)
	}
	if len(keyBytes) != 32 {
		return nil, fmt.Errorf("email crypto: master key must be 32 bytes (got %d)", len(keyBytes))
	}
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("email crypto: new cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("email crypto: new gcm: %w", err)
	}
	return &SecretCrypto{aead: aead}, nil
}

// Encrypt produces (ciphertext, nonce) from a plaintext API key.
func (c *SecretCrypto) Encrypt(plaintext string) (ciphertext, nonce []byte, err error) {
	if c == nil || c.aead == nil {
		return nil, nil, errors.New("email crypto: not initialized")
	}
	nonce = make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("email crypto: random nonce: %w", err)
	}
	ciphertext = c.aead.Seal(nil, nonce, []byte(plaintext), nil)
	return ciphertext, nonce, nil
}

// Decrypt reverses Encrypt and returns the plaintext API key.
func (c *SecretCrypto) Decrypt(ciphertext, nonce []byte) (string, error) {
	if c == nil || c.aead == nil {
		return "", errors.New("email crypto: not initialized")
	}
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("email crypto: decrypt: %w", err)
	}
	return string(plaintext), nil
}

// LastFour returns a redacted preview of an API key suitable for display
// to admins. Falls back to the whole key if shorter than 8 chars.
func LastFour(apiKey string) string {
	if len(apiKey) < 8 {
		return apiKey
	}
	return apiKey[len(apiKey)-4:]
}
