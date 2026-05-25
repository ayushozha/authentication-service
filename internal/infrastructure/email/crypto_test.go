package email

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestSecretCryptoRoundTrip(t *testing.T) {
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatalf("rand: %v", err)
	}
	c, err := NewSecretCrypto(base64.StdEncoding.EncodeToString(master))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	plaintext := "re_test_1234567890ABCDEFGHIJKL"
	ct, nonce, err := c.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if len(ct) == 0 || len(nonce) == 0 {
		t.Fatal("empty ciphertext or nonce")
	}
	got, err := c.Decrypt(ct, nonce)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if got != plaintext {
		t.Fatalf("got %q want %q", got, plaintext)
	}
}

func TestSecretCryptoRejectsWrongLength(t *testing.T) {
	short := base64.StdEncoding.EncodeToString(make([]byte, 16))
	if _, err := NewSecretCrypto(short); err == nil {
		t.Fatal("expected error for 16-byte key")
	}
}

func TestLastFour(t *testing.T) {
	if got := LastFour("re_live_abcdefghij1234"); got != "1234" {
		t.Fatalf("got %q", got)
	}
	if got := LastFour("short"); got != "short" {
		t.Fatalf("expected passthrough for short, got %q", got)
	}
}
