package application

import (
	"errors"
	"testing"

	"github.com/Ayush10/authentication-service/internal/domain"
)

func TestNormalizeEmailAddress(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "lowercases and trims", input: " User@Example.COM ", want: "user@example.com"},
		{name: "allows common local characters", input: "first.last+tag@example.co.uk", want: "first.last+tag@example.co.uk"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeEmailAddress(tt.input)
			if err != nil {
				t.Fatalf("NormalizeEmailAddress(%q) returned error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("NormalizeEmailAddress(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeEmailAddressRejectsInvalidFormats(t *testing.T) {
	invalid := []string{
		"",
		"mail",
		"Name <user@example.com>",
		"user@example",
		"user@localhost",
		"user@@example.com",
		".user@example.com",
		"user..name@example.com",
		"user@example..com",
		"user@-example.com",
		"user@example.c",
		"user@exa_mple.com",
		`"user"@example.com`,
	}

	for _, input := range invalid {
		t.Run(input, func(t *testing.T) {
			if got, err := NormalizeEmailAddress(input); !errors.Is(err, domain.ErrInvalidEmail) {
				t.Fatalf("NormalizeEmailAddress(%q) = %q, %v; want ErrInvalidEmail", input, got, err)
			}
		})
	}
}
