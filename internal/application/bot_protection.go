package application

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Ayush10/authentication-service/internal/domain"
)

type BotVerifier interface {
	Verify(ctx context.Context, token, remoteIP string) error
}

type BotProtectionConfig struct {
	SignupRequired bool
	LoginRequired  bool
	Verifier       BotVerifier
}

type HTTPBotVerifier struct {
	provider  string
	secret    string
	verifyURL string
	client    *http.Client
}

var botProtection BotProtectionConfig

func SetBotProtection(config BotProtectionConfig) {
	botProtection = config
}

func NewHTTPBotVerifier(provider, secret, verifyURL string, timeout time.Duration) *HTTPBotVerifier {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	provider = strings.ToLower(strings.TrimSpace(provider))
	verifyURL = strings.TrimSpace(verifyURL)
	if verifyURL == "" {
		verifyURL = defaultBotVerifyURL(provider)
	}
	return &HTTPBotVerifier{
		provider:  provider,
		secret:    strings.TrimSpace(secret),
		verifyURL: verifyURL,
		client:    &http.Client{Timeout: timeout},
	}
}

func (v *HTTPBotVerifier) Verify(ctx context.Context, token, remoteIP string) error {
	if v == nil || v.secret == "" || v.verifyURL == "" || strings.TrimSpace(token) == "" {
		return domain.ErrBotVerification
	}
	form := url.Values{}
	form.Set("secret", v.secret)
	form.Set("response", strings.TrimSpace(token))
	if remoteIP = strings.TrimSpace(remoteIP); remoteIP != "" {
		form.Set("remoteip", remoteIP)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.verifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return domain.ErrBotVerification
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := v.client.Do(req)
	if err != nil {
		return domain.ErrBotVerification
	}
	defer res.Body.Close()

	var payload struct {
		Success bool `json:"success"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		return domain.ErrBotVerification
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 || !payload.Success {
		return domain.ErrBotVerification
	}
	return nil
}

func defaultBotVerifyURL(provider string) string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "turnstile", "cloudflare":
		return "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	case "hcaptcha":
		return "https://hcaptcha.com/siteverify"
	case "recaptcha", "recaptcha-v2", "recaptcha-v3":
		return "https://www.google.com/recaptcha/api/siteverify"
	default:
		return ""
	}
}

func verifyBotToken(ctx context.Context, required bool, token, ip string) error {
	if !required {
		return nil
	}
	if botProtection.Verifier == nil {
		return domain.ErrBotVerification
	}
	return botProtection.Verifier.Verify(ctx, token, ip)
}
