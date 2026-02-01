package domain

import "errors"

var (
	ErrNotFound          = errors.New("not found")
	ErrDuplicateEmail    = errors.New("email already registered")
	ErrInvalidToken      = errors.New("invalid or expired token")
	ErrInvalidPassword   = errors.New("invalid email or password")
	ErrAccountSuspended  = errors.New("account is suspended")
	ErrAccountLocked     = errors.New("account temporarily locked")
	ErrTOTPRequired      = errors.New("2FA verification required")
	ErrTOTPInvalid       = errors.New("invalid TOTP code")
	ErrTOTPAlreadyOn     = errors.New("TOTP already enabled")
	ErrTOTPNotEnabled    = errors.New("TOTP not enabled")
	ErrTOTPNoPending     = errors.New("no TOTP setup pending")
	ErrRedisRequired     = errors.New("this feature requires Redis")
	ErrEmailNotConfigured = errors.New("email sending not configured")
	ErrRateLimit         = errors.New("too many requests, try again later")
	ErrWeakPassword      = errors.New("password does not meet strength requirements")
	ErrEmailAlreadyVerified = errors.New("email already verified")
	ErrInvalidClient     = errors.New("invalid API key")
	ErrClientSuspended   = errors.New("client is suspended")
)
