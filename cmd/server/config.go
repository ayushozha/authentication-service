package main

import (
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Port             string
	GRPCPort         string
	PublicDir        string
	ServeFrontend    bool
	DatabaseURL      string
	RedisURL         string
	RedisPrefix      string
	AllowOrigin      string
	AdminAPIKey      string
	AdminTokenSecret string
	AdminAccessTTL   time.Duration
	BaseURL          string

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

	PasswordMinLength     int
	PasswordMaxLength     int
	PasswordMinUnique     int
	PasswordBlockCommon   bool
	PasswordBlockUserInfo bool
	BlockedEmailDomains   []string

	WebhookSigningSecret string
	WebhookRetryAttempts int
	WebhookTimeout       time.Duration

	AuditRetentionDays       int
	AuditStreamProviders     []string
	AuditStreamTimeout       time.Duration
	AuditStreamRetryAttempts int
	DatadogLogsURL           string
	DatadogAPIKey            string
	SplunkHECURL             string
	SplunkHECToken           string
	ElasticBulkURL           string
	ElasticAPIKey            string
	ElasticIndex             string
	AWSRegion                string
	AWSAccessKeyID           string
	AWSSecretAccessKey       string
	AWSSessionToken          string
	AuditS3Bucket            string
	AuditS3Prefix            string
	AuditCloudWatchLogGroup  string
	AuditCloudWatchLogStream string
	GCPProjectID             string
	GCPLogID                 string
	GCPAccessToken           string
	GCPLoggingURL            string
	AzureMonitorIngestURL    string
	AzureMonitorBearerToken  string

	CaptchaProvider       string
	CaptchaSecret         string
	CaptchaVerifyURL      string
	CaptchaTimeout        time.Duration
	CaptchaSignupRequired bool
	CaptchaLoginRequired  bool

	RiskProviderURL     string
	RiskProviderAPIKey  string
	RiskProviderTimeout time.Duration
}

func loadConfig() Config {
	accessTTL, _ := time.ParseDuration(envStr("JWT_ACCESS_TTL", "15m"))
	refreshTTL, _ := time.ParseDuration(envStr("JWT_REFRESH_TTL", "168h"))
	adminAccessTTL, _ := time.ParseDuration(envStr("ADMIN_ACCESS_TTL", "8h"))
	bcryptCost, _ := strconv.Atoi(envStr("BCRYPT_COST", "12"))
	if bcryptCost < 10 || bcryptCost > 16 {
		bcryptCost = 12
	}
	passwordMinLength, _ := strconv.Atoi(envStr("PASSWORD_MIN_LENGTH", "8"))
	passwordMaxLength, _ := strconv.Atoi(envStr("PASSWORD_MAX_LENGTH", "72"))
	passwordMinUnique, _ := strconv.Atoi(envStr("PASSWORD_MIN_UNIQUE", "4"))
	webhookRetryAttempts, _ := strconv.Atoi(envStr("WEBHOOK_RETRY_ATTEMPTS", "3"))
	if webhookRetryAttempts < 1 || webhookRetryAttempts > 10 {
		webhookRetryAttempts = 3
	}
	webhookTimeout, err := time.ParseDuration(envStr("WEBHOOK_TIMEOUT", "5s"))
	if err != nil || webhookTimeout <= 0 {
		webhookTimeout = 5 * time.Second
	}
	auditRetentionDays, _ := strconv.Atoi(envStr("AUDIT_RETENTION_DAYS", "2555"))
	if auditRetentionDays <= 0 {
		auditRetentionDays = 2555
	}
	auditStreamRetryAttempts, _ := strconv.Atoi(envStr("AUDIT_STREAM_RETRY_ATTEMPTS", "3"))
	if auditStreamRetryAttempts < 1 || auditStreamRetryAttempts > 10 {
		auditStreamRetryAttempts = 3
	}
	auditStreamTimeout, err := time.ParseDuration(envStr("AUDIT_STREAM_TIMEOUT", "5s"))
	if err != nil || auditStreamTimeout <= 0 {
		auditStreamTimeout = 5 * time.Second
	}
	captchaTimeout, err := time.ParseDuration(envStr("CAPTCHA_TIMEOUT", "5s"))
	if err != nil || captchaTimeout <= 0 {
		captchaTimeout = 5 * time.Second
	}
	riskProviderTimeout, err := time.ParseDuration(envStr("RISK_PROVIDER_TIMEOUT", "5s"))
	if err != nil || riskProviderTimeout <= 0 {
		riskProviderTimeout = 5 * time.Second
	}
	blockedEmailDomains := envList("BLOCKED_EMAIL_DOMAINS", []string{
		"10minutemail.com",
		"dispostable.com",
		"guerrillamail.com",
		"guerrillamail.net",
		"mailinator.com",
		"maildrop.cc",
		"sharklasers.com",
		"tempmail.com",
		"throwawaymail.com",
		"yopmail.com",
	})

	serveFrontend := envStr("SERVE_FRONTEND", "true") == "true"
	baseURL := envStr("BASE_URL", "http://localhost:8080")
	cookieSecureEnv := strings.TrimSpace(os.Getenv("COOKIE_SECURE"))
	cookieSecure := strings.EqualFold(cookieSecureEnv, "true") || (cookieSecureEnv == "" && strings.HasPrefix(baseURL, "https://"))
	cookieSameSite := strings.TrimSpace(os.Getenv("COOKIE_SAMESITE"))
	if cookieSameSite == "" {
		if cookieSecure {
			cookieSameSite = "none"
		} else {
			cookieSameSite = "lax"
		}
	}

	return Config{
		Port:             envStr("PORT", "8080"),
		GRPCPort:         envStr("GRPC_PORT", "9090"),
		PublicDir:        envStr("PUBLIC_DIR", "./public"),
		ServeFrontend:    serveFrontend,
		DatabaseURL:      envStr("DATABASE_URL", ""),
		RedisURL:         envStr("REDIS_URL", ""),
		RedisPrefix:      envStr("REDIS_KEY_PREFIX", "auth:"),
		AllowOrigin:      envStr("ALLOW_ORIGIN", "*"),
		AdminAPIKey:      envStr("ADMIN_API_KEY", ""),
		AdminTokenSecret: envStr("ADMIN_TOKEN_SECRET", envStr("ADMIN_API_KEY", "")),
		AdminAccessTTL:   adminAccessTTL,
		BaseURL:          baseURL,

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
		CookieSameSite: cookieSameSite,
		CookieDomain:   envStr("COOKIE_DOMAIN", ""),

		PasswordMinLength:     passwordMinLength,
		PasswordMaxLength:     passwordMaxLength,
		PasswordMinUnique:     passwordMinUnique,
		PasswordBlockCommon:   envStr("PASSWORD_BLOCK_COMMON", "true") == "true",
		PasswordBlockUserInfo: envStr("PASSWORD_BLOCK_USER_INFO", "true") == "true",
		BlockedEmailDomains:   blockedEmailDomains,

		WebhookSigningSecret: envStr("WEBHOOK_SIGNING_SECRET", ""),
		WebhookRetryAttempts: webhookRetryAttempts,
		WebhookTimeout:       webhookTimeout,

		AuditRetentionDays:       auditRetentionDays,
		AuditStreamProviders:     envList("AUDIT_STREAMS", nil),
		AuditStreamTimeout:       auditStreamTimeout,
		AuditStreamRetryAttempts: auditStreamRetryAttempts,
		DatadogLogsURL:           envStr("DATADOG_LOGS_URL", ""),
		DatadogAPIKey:            envStr("DATADOG_API_KEY", ""),
		SplunkHECURL:             envStr("SPLUNK_HEC_URL", ""),
		SplunkHECToken:           envStr("SPLUNK_HEC_TOKEN", ""),
		ElasticBulkURL:           envStr("ELASTIC_BULK_URL", ""),
		ElasticAPIKey:            envStr("ELASTIC_API_KEY", ""),
		ElasticIndex:             envStr("ELASTIC_INDEX", "authservice-audit"),
		AWSRegion:                envStr("AWS_REGION", ""),
		AWSAccessKeyID:           envStr("AWS_ACCESS_KEY_ID", ""),
		AWSSecretAccessKey:       envStr("AWS_SECRET_ACCESS_KEY", ""),
		AWSSessionToken:          envStr("AWS_SESSION_TOKEN", ""),
		AuditS3Bucket:            envStr("AUDIT_S3_BUCKET", ""),
		AuditS3Prefix:            envStr("AUDIT_S3_PREFIX", "authservice/audit"),
		AuditCloudWatchLogGroup:  envStr("AUDIT_CLOUDWATCH_LOG_GROUP", ""),
		AuditCloudWatchLogStream: envStr("AUDIT_CLOUDWATCH_LOG_STREAM", ""),
		GCPProjectID:             envStr("GCP_PROJECT_ID", ""),
		GCPLogID:                 envStr("GCP_LOG_ID", "authservice-audit"),
		GCPAccessToken:           envStr("GCP_ACCESS_TOKEN", ""),
		GCPLoggingURL:            envStr("GCP_LOGGING_URL", ""),
		AzureMonitorIngestURL:    envStr("AZURE_MONITOR_INGEST_URL", ""),
		AzureMonitorBearerToken:  envStr("AZURE_MONITOR_BEARER_TOKEN", ""),

		CaptchaProvider:       envStr("CAPTCHA_PROVIDER", ""),
		CaptchaSecret:         envStr("CAPTCHA_SECRET", ""),
		CaptchaVerifyURL:      envStr("CAPTCHA_VERIFY_URL", ""),
		CaptchaTimeout:        captchaTimeout,
		CaptchaSignupRequired: envStr("CAPTCHA_SIGNUP_REQUIRED", "false") == "true",
		CaptchaLoginRequired:  envStr("CAPTCHA_LOGIN_REQUIRED", "false") == "true",

		RiskProviderURL:     envStr("RISK_PROVIDER_URL", ""),
		RiskProviderAPIKey:  envStr("RISK_PROVIDER_API_KEY", ""),
		RiskProviderTimeout: riskProviderTimeout,
	}
}

func envStr(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func envList(key string, fallback []string) []string {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	parts := strings.Split(raw, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			values = append(values, part)
		}
	}
	return values
}
