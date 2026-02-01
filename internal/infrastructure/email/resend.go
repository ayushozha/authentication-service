package email

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"time"
)

//go:embed templates/*.html
var emailTemplatesFS embed.FS

var emailTemplates = template.Must(template.ParseFS(emailTemplatesFS, "templates/*.html"))

type ResendClient struct {
	apiKey string
	from   string
}

func NewResendClient(apiKey, from string) *ResendClient {
	if apiKey == "" {
		return nil
	}
	return &ResendClient{apiKey: apiKey, from: from}
}

type resendRequest struct {
	From    string   `json:"from"`
	To      []string `json:"to"`
	Subject string   `json:"subject"`
	HTML    string   `json:"html"`
}

func (e *ResendClient) Send(to, subject, htmlBody string) error {
	payload, err := json.Marshal(resendRequest{
		From:    e.from,
		To:      []string{to},
		Subject: subject,
		HTML:    htmlBody,
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

func (e *ResendClient) SendVerifyEmail(to, displayName, verifyURL string) error {
	var buf bytes.Buffer
	if err := emailTemplates.ExecuteTemplate(&buf, "verify_email.html", map[string]string{
		"DisplayName": displayName,
		"VerifyURL":   verifyURL,
	}); err != nil {
		return fmt.Errorf("render verify email template: %w", err)
	}
	return e.Send(to, "Verify your email", buf.String())
}

func (e *ResendClient) SendPasswordReset(to, displayName, resetURL string) error {
	var buf bytes.Buffer
	if err := emailTemplates.ExecuteTemplate(&buf, "password_reset.html", map[string]string{
		"DisplayName": displayName,
		"ResetURL":    resetURL,
	}); err != nil {
		return fmt.Errorf("render password reset template: %w", err)
	}
	return e.Send(to, "Reset your password", buf.String())
}

func (e *ResendClient) SendMagicLink(to, magicURL string) error {
	var buf bytes.Buffer
	if err := emailTemplates.ExecuteTemplate(&buf, "magic_link.html", map[string]string{
		"MagicURL": magicURL,
	}); err != nil {
		return fmt.Errorf("render magic link template: %w", err)
	}
	return e.Send(to, "Sign in to your account", buf.String())
}

func (e *ResendClient) SendVerifyEmailAsync(to, displayName, verifyURL string) {
	go func() {
		if err := e.SendVerifyEmail(to, displayName, verifyURL); err != nil {
			log.Printf("send verify email error: %v", err)
		}
	}()
}

func (e *ResendClient) SendPasswordResetAsync(to, displayName, resetURL string) {
	go func() {
		if err := e.SendPasswordReset(to, displayName, resetURL); err != nil {
			log.Printf("send password reset email error: %v", err)
		}
	}()
}

func (e *ResendClient) SendMagicLinkAsync(to, magicURL string) {
	go func() {
		if err := e.SendMagicLink(to, magicURL); err != nil {
			log.Printf("send magic link email error: %v", err)
		}
	}()
}
