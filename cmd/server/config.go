package main

import (
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Port          string
	GRPCPort      string
	PublicDir     string
	ServeFrontend bool
	DatabaseURL   string
	RedisURL      string
	RedisPrefix   string
	AllowOrigin   string
	AdminAPIKey   string
	BaseURL       string

	// JWT defaults
	JWTAccessTTL  time.Duration
	JWTRefreshTTL time.Duration

	// Email (Resend)
	ResendAPIKey string
	EmailFrom    string

	// OAuth
	GoogleClientID     string
	GoogleClientSecret string
	GoogleRedirectURL  string

	GithubClientID     string
	GithubClientSecret string
	GithubRedirectURL  string

	MicrosoftClientID     string
	MicrosoftClientSecret string
	MicrosoftTenantID     string
	MicrosoftRedirectURL  string

	AppleClientID    string
	AppleRedirectURL string

	// WebAuthn
	WebAuthnRPID     string
	WebAuthnRPOrigin string
	WebAuthnRPName   string

	// Security
	BcryptCost     int
	CookieSecure   bool
	CookieSameSite string
	CookieDomain   string
}

func loadConfig() Config {
	accessTTL, _ := time.ParseDuration(envStr("JWT_ACCESS_TTL", "15m"))
	refreshTTL, _ := time.ParseDuration(envStr("JWT_REFRESH_TTL", "168h"))
	bcryptCost, _ := strconv.Atoi(envStr("BCRYPT_COST", "12"))
	if bcryptCost < 10 || bcryptCost > 16 {
		bcryptCost = 12
	}

	serveFrontend := envStr("SERVE_FRONTEND", "true") == "true"
	cookieSecure := envStr("COOKIE_SECURE", "false") == "true"

	return Config{
		Port:          envStr("PORT", "8080"),
		GRPCPort:      envStr("GRPC_PORT", "9090"),
		PublicDir:     envStr("PUBLIC_DIR", "./public"),
		ServeFrontend: serveFrontend,
		DatabaseURL:   envStr("DATABASE_URL", ""),
		RedisURL:      envStr("REDIS_URL", ""),
		RedisPrefix:   envStr("REDIS_KEY_PREFIX", "auth:"),
		AllowOrigin:   envStr("ALLOW_ORIGIN", "*"),
		AdminAPIKey:   envStr("ADMIN_API_KEY", ""),
		BaseURL:       envStr("BASE_URL", "http://localhost:8080"),

		JWTAccessTTL:  accessTTL,
		JWTRefreshTTL: refreshTTL,

		ResendAPIKey: envStr("RESEND_API_KEY", ""),
		EmailFrom:    envStr("EMAIL_FROM", "Auth Service <noreply@example.com>"),

		GoogleClientID:     envStr("GOOGLE_CLIENT_ID", ""),
		GoogleClientSecret: envStr("GOOGLE_CLIENT_SECRET", ""),
		GoogleRedirectURL:  envStr("GOOGLE_REDIRECT_URL", ""),

		GithubClientID:     envStr("GITHUB_CLIENT_ID", ""),
		GithubClientSecret: envStr("GITHUB_CLIENT_SECRET", ""),
		GithubRedirectURL:  envStr("GITHUB_REDIRECT_URL", ""),

		MicrosoftClientID:     envStr("MICROSOFT_CLIENT_ID", ""),
		MicrosoftClientSecret: envStr("MICROSOFT_CLIENT_SECRET", ""),
		MicrosoftTenantID:     envStr("MICROSOFT_TENANT_ID", "common"),
		MicrosoftRedirectURL:  envStr("MICROSOFT_REDIRECT_URL", ""),

		AppleClientID:    envStr("APPLE_CLIENT_ID", ""),
		AppleRedirectURL: envStr("APPLE_REDIRECT_URL", ""),

		WebAuthnRPID:     envStr("WEBAUTHN_RP_ID", "localhost"),
		WebAuthnRPOrigin: envStr("WEBAUTHN_RP_ORIGIN", "http://localhost:8080"),
		WebAuthnRPName:   envStr("WEBAUTHN_DISPLAY_NAME", "Auth Service"),

		BcryptCost:     bcryptCost,
		CookieSecure:   cookieSecure,
		CookieSameSite: envStr("COOKIE_SAMESITE", "lax"),
		CookieDomain:   envStr("COOKIE_DOMAIN", ""),
	}
}

func envStr(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}
