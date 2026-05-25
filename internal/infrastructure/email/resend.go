package email

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"time"
)

//go:embed templates/*.html
var emailTemplatesFS embed.FS

var emailTemplates = template.Must(template.ParseFS(emailTemplatesFS, "templates/*.html"))

// resendTransport is the low-level Resend HTTP client. Each call site that
// resolves a different (apiKey, from) pair gets its own transport — they're
// cheap (no connection state of consequence) and held by the RouterMailer
// for short-lived dispatch.
type resendTransport struct {
	apiKey  string
	from    string
	replyTo string
}

func newResendTransport(apiKey, from, replyTo string) *resendTransport {
	if apiKey == "" || from == "" {
		return nil
	}
	return &resendTransport{apiKey: apiKey, from: from, replyTo: replyTo}
}

type resendRequest struct {
	From    string   `json:"from"`
	To      []string `json:"to"`
	Subject string   `json:"subject"`
	HTML    string   `json:"html"`
	ReplyTo string   `json:"reply_to,omitempty"`
}

func (e *resendTransport) Send(to, subject, htmlBody string) error {
	payload, err := json.Marshal(resendRequest{
		From:    e.from,
		To:      []string{to},
		Subject: subject,
		HTML:    htmlBody,
		ReplyTo: e.replyTo,
	})
	if err != nil {
		return fmt.Errorf("marshal email: %w", err)
	}

	req, err := http.NewRequest("POST", "https://api.resend.com/emails", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+e.apiKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("send email: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("resend API error %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (e *resendTransport) SendVerifyEmail(to, displayName, verifyURL string) error {
	var buf bytes.Buffer
	if err := emailTemplates.ExecuteTemplate(&buf, "verify_email.html", map[string]string{
		"DisplayName": displayName,
		"VerifyURL":   verifyURL,
	}); err != nil {
		return fmt.Errorf("render verify email template: %w", err)
	}
	return e.Send(to, "Verify your email", buf.String())
}

func (e *resendTransport) SendPasswordReset(to, displayName, resetURL string) error {
	var buf bytes.Buffer
	if err := emailTemplates.ExecuteTemplate(&buf, "password_reset.html", map[string]string{
		"DisplayName": displayName,
		"ResetURL":    resetURL,
	}); err != nil {
		return fmt.Errorf("render password reset template: %w", err)
	}
	return e.Send(to, "Reset your password", buf.String())
}

func (e *resendTransport) SendMagicLink(to, magicURL string) error {
	var buf bytes.Buffer
	if err := emailTemplates.ExecuteTemplate(&buf, "magic_link.html", map[string]string{
		"MagicURL": magicURL,
	}); err != nil {
		return fmt.Errorf("render magic link template: %w", err)
	}
	return e.Send(to, "Sign in to your account", buf.String())
}
