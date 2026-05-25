package main

import (
	"log"
	"net"
	"net/http"
	"time"

	"github.com/Ayush10/authentication-service/internal/application"
	"github.com/Ayush10/authentication-service/internal/infrastructure/email"
	"github.com/Ayush10/authentication-service/internal/infrastructure/postgres"
	redisclient "github.com/Ayush10/authentication-service/internal/infrastructure/redis"
	authgrpc "github.com/Ayush10/authentication-service/internal/interfaces/grpc"
	"github.com/Ayush10/authentication-service/internal/interfaces/rest"
)

func main() {
	cfg := loadConfig()

	if cfg.DatabaseURL == "" {
		log.Fatal("DATABASE_URL environment variable is required")
	}

	if cfg.AdminAPIKey == "" {
		log.Fatal("ADMIN_API_KEY environment variable is required")
	}

	// Database
	db, err := postgres.OpenDB(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("database connection: %v", err)
	}

	if err := postgres.RunMigrations(db); err != nil {
		log.Fatalf("migrations: %v", err)
	}

	metricsRegistry := application.NewMetricsRegistry()
	application.SetMetricsRegistry(metricsRegistry)
	auditStream := application.NewAuditLogStream(application.AuditLogStreamConfig{
		Providers:               cfg.AuditStreamProviders,
		Timeout:                 cfg.AuditStreamTimeout,
		Attempts:                cfg.AuditStreamRetryAttempts,
		Service:                 "authservice",
		Env:                     cfg.BaseURL,
		DatadogURL:              cfg.DatadogLogsURL,
		DatadogAPIKey:           cfg.DatadogAPIKey,
		SplunkHECURL:            cfg.SplunkHECURL,
		SplunkHECToken:          cfg.SplunkHECToken,
		ElasticBulkURL:          cfg.ElasticBulkURL,
		ElasticAPIKey:           cfg.ElasticAPIKey,
		ElasticIndex:            cfg.ElasticIndex,
		AWSRegion:               cfg.AWSRegion,
		AWSAccessKeyID:          cfg.AWSAccessKeyID,
		AWSSecretAccessKey:      cfg.AWSSecretAccessKey,
		AWSSessionToken:         cfg.AWSSessionToken,
		S3Bucket:                cfg.AuditS3Bucket,
		S3Prefix:                cfg.AuditS3Prefix,
		CloudWatchLogGroup:      cfg.AuditCloudWatchLogGroup,
		CloudWatchLogStream:     cfg.AuditCloudWatchLogStream,
		GCPProjectID:            cfg.GCPProjectID,
		GCPLogID:                cfg.GCPLogID,
		GCPAccessToken:          cfg.GCPAccessToken,
		GCPLoggingURL:           cfg.GCPLoggingURL,
		AzureMonitorURL:         cfg.AzureMonitorIngestURL,
		AzureMonitorBearerToken: cfg.AzureMonitorBearerToken,
	})
	auditSink := application.NewCompositeAuditEventSink(
		application.NewMetricsAuditSink(metricsRegistry),
		auditStream,
	)

	// Redis (optional)
	rdb, err := redisclient.NewClient(cfg.RedisURL, cfg.RedisPrefix)
	if err != nil {
		log.Printf("WARNING: Redis unavailable: %v", err)
	}

	// Repositories
	clientRepo := postgres.NewClientRepo(db)
	emailConfigRepo := postgres.NewClientEmailConfigRepo(db)
	userRepo := postgres.NewUserRepo(db)
	sessionRepo := postgres.NewSessionRepo(db)
	oauthRepo := postgres.NewOAuthRepo(db)
	webauthnRepo := postgres.NewWebAuthnRepo(db)
	tokenRepo := postgres.NewTokenRepo(db)
	recoveryCodeRepo := postgres.NewRecoveryCodeRepo(db)
	auditRepo := postgres.NewAuditRepo(
		db,
		postgres.WithAuditRetentionDays(cfg.AuditRetentionDays),
		postgres.WithAuditEventSink(auditSink),
	)
	adminRepo := postgres.NewAdminRepo(db)
	userDeviceRepo := postgres.NewUserDeviceRepo(db)
	signingKeyRepo := postgres.NewSigningKeyRepo(db)
	orgRepo := postgres.NewOrganizationRepo(db)
	serviceAccountRepo := postgres.NewServiceAccountRepo(db)
	ssoRepo := postgres.NewEnterpriseSSORepo(db)
	scimRepo := postgres.NewSCIMRepo(db)
	enterpriseOnboardingRepo := postgres.NewEnterpriseOnboardingRepo(db)
	application.SetSigningKeyRepository(signingKeyRepo)
	application.SetPasswordPolicy(application.PasswordPolicy{
		MinLength:     cfg.PasswordMinLength,
		MaxLength:     cfg.PasswordMaxLength,
		MinUnique:     cfg.PasswordMinUnique,
		BlockCommon:   cfg.PasswordBlockCommon,
		BlockUserInfo: cfg.PasswordBlockUserInfo,
	})
	application.SetBlockedSignupEmailDomains(cfg.BlockedEmailDomains)
	application.SetBotProtection(application.BotProtectionConfig{
		SignupRequired: cfg.CaptchaSignupRequired,
		LoginRequired:  cfg.CaptchaLoginRequired,
		Verifier: application.NewHTTPBotVerifier(
			cfg.CaptchaProvider,
			cfg.CaptchaSecret,
			cfg.CaptchaVerifyURL,
			cfg.CaptchaTimeout,
		),
	})

	// Rate limiter
	rl := redisclient.NewRateLimiter(rdb)

	// Audit writes are always stored locally. When configured, the same events are
	// also delivered to the client webhook URL with HMAC signatures and retries.
	var auditEvents application.AuditRepository = auditRepo
	if cfg.WebhookSigningSecret != "" {
		auditEvents = application.NewWebhookAuditRepository(
			auditRepo,
			clientRepo,
			cfg.WebhookSigningSecret,
			cfg.WebhookRetryAttempts,
			cfg.WebhookTimeout,
		)
	}

	// Email client — hybrid: per-client overrides on top of a global Resend fallback.
	// The router resolves the right transport per request based on client_email_configs.
	var emailCrypto *email.SecretCrypto
	if cfg.EmailConfigKMSKey != "" {
		c, err := email.NewSecretCrypto(cfg.EmailConfigKMSKey)
		if err != nil {
			log.Fatalf("email crypto: %v", err)
		}
		emailCrypto = c
	} else {
		log.Printf("WARNING: EMAIL_CONFIG_KMS_KEY not set; per-client email overrides disabled (fallback transport only)")
	}
	var mailer application.EmailSender = email.NewRouterMailer(emailConfigRepo, emailCrypto, cfg.ResendAPIKey, cfg.EmailFrom, cfg.EmailReplyTo)
	if cfg.ResendAPIKey == "" {
		log.Printf("WARNING: RESEND_API_KEY not set; clients without per-client email config will fail to deliver mail")
	}
	emailURLBuilder := application.NewEmailURLBuilder(emailConfigRepo, cfg.BaseURL)

	// Application services
	clientSvc := application.NewClientService(clientRepo)
	emailConfigSvc := application.NewClientEmailConfigService(clientRepo, emailConfigRepo, emailCrypto)
	adminSvc := application.NewAdminService(adminRepo, auditRepo, rl, cfg.AdminTokenSecret, cfg.AdminAccessTTL)
	authSvc := application.NewAuthService(userRepo, sessionRepo, rdb, auditEvents, rl)
	verifySvc := application.NewEmailVerifyService(userRepo, tokenRepo, mailer, emailURLBuilder)
	resetSvc := application.NewPasswordResetService(userRepo, tokenRepo, sessionRepo, mailer, emailURLBuilder, rl)
	magicSvc := application.NewMagicLinkService(clientRepo, userRepo, sessionRepo, rdb, mailer, emailURLBuilder, auditEvents, rl)
	totpSvc := application.NewTOTPService(userRepo, sessionRepo, rdb, auditEvents, recoveryCodeRepo)
	oauthSvc := application.NewOAuthService(userRepo, clientRepo, oauthRepo, sessionRepo, rdb, auditEvents)
	auditSvc := application.NewAuditService(auditRepo)
	orgSvc := application.NewOrganizationService(orgRepo, userRepo, auditEvents)
	riskProvider := application.NewHTTPRiskSignalProvider(cfg.RiskProviderURL, cfg.RiskProviderAPIKey, cfg.RiskProviderTimeout)
	adaptiveSvc := application.NewAdaptiveSecurityService(clientRepo, orgRepo, userRepo, sessionRepo, userDeviceRepo, recoveryCodeRepo, rdb, auditEvents, riskProvider)
	adaptiveSvc.SetAdminUsers(adminRepo)
	authSvc.SetAdaptiveSecurity(adaptiveSvc)
	totpSvc.SetAdaptiveSecurity(adaptiveSvc)
	m2mSvc := application.NewM2MService(serviceAccountRepo, clientRepo, auditEvents)
	ssoSvc := application.NewEnterpriseSSOService(ssoRepo, userRepo, clientRepo, sessionRepo, rdb, auditEvents, orgRepo)
	authSvc.SetEnterpriseSSORepository(ssoRepo)
	resetSvc.SetEnterpriseSSORepository(ssoRepo)
	magicSvc.SetEnterpriseSSORepository(ssoRepo)
	oauthSvc.SetEnterpriseSSORepository(ssoRepo)
	scimSvc := application.NewSCIMService(scimRepo, userRepo, auditEvents, orgRepo)
	enterpriseOnboardingSvc := application.NewEnterpriseOnboardingService(enterpriseOnboardingRepo, orgRepo, ssoRepo, scimRepo, auditRepo, ssoSvc)
	oidcSvc := application.NewOIDCService(clientRepo, userRepo, sessionRepo, rdb, auditEvents)

	// Wire signup email hook
	verifySvc.WireSignupHook()

	// OAuth providers
	oauthProviders := application.BuildOAuthProviders(application.OAuthConfig{
		GoogleClientID:        cfg.GoogleClientID,
		GoogleClientSecret:    cfg.GoogleClientSecret,
		GoogleRedirectURL:     cfg.GoogleRedirectURL,
		GithubClientID:        cfg.GithubClientID,
		GithubClientSecret:    cfg.GithubClientSecret,
		GithubRedirectURL:     cfg.GithubRedirectURL,
		MicrosoftClientID:     cfg.MicrosoftClientID,
		MicrosoftClientSecret: cfg.MicrosoftClientSecret,
		MicrosoftTenantID:     cfg.MicrosoftTenantID,
		MicrosoftRedirectURL:  cfg.MicrosoftRedirectURL,
		AppleClientID:         cfg.AppleClientID,
		AppleRedirectURL:      cfg.AppleRedirectURL,
	})

	// Passkey service (optional)
	var passkeySvc *application.PasskeyService
	passkeySvc, err = application.NewPasskeyService(
		userRepo, webauthnRepo, sessionRepo, rdb, auditEvents,
		cfg.WebAuthnRPName, cfg.WebAuthnRPID, cfg.WebAuthnRPOrigin,
	)
	if err != nil {
		log.Printf("WARNING: WebAuthn initialization failed: %v", err)
		passkeySvc = nil
	}

	// Handler config
	handlerCfg := &rest.HandlerConfig{
		AllowOrigin:    cfg.AllowOrigin,
		BaseURL:        cfg.BaseURL,
		Cache:          rdb,
		BcryptCost:     cfg.BcryptCost,
		AccessTTL:      cfg.JWTAccessTTL,
		RefreshTTL:     cfg.JWTRefreshTTL,
		CookieSecure:   cfg.CookieSecure,
		CookieSameSite: cfg.CookieSameSite,
		CookieDomain:   cfg.CookieDomain,
	}

	// Router
	router := rest.NewRouter(
		authSvc, verifySvc, resetSvc, magicSvc, totpSvc,
		oauthSvc, passkeySvc, adminSvc, clientSvc, emailConfigSvc, auditSvc, orgSvc, adaptiveSvc, m2mSvc, ssoSvc, scimSvc,
		enterpriseOnboardingSvc, oidcSvc,
		oauthProviders, handlerCfg,
		cfg.AdminAPIKey, cfg.ServeFrontend, cfg.PublicDir,
	)

	// HTTP Server
	server := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           router.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// gRPC Server
	grpcSrv := authgrpc.NewServer(authgrpc.Config{
		AuthService:          authSvc,
		EmailVerifyService:   verifySvc,
		PasswordResetService: resetSvc,
		MagicLinkService:     magicSvc,
		ClientService:        clientSvc,
		AdminService:         adminSvc,
		AdminAPIKey:          cfg.AdminAPIKey,
		BcryptCost:           cfg.BcryptCost,
		AccessTTL:            cfg.JWTAccessTTL,
		RefreshTTL:           cfg.JWTRefreshTTL,
		BaseURL:              cfg.BaseURL,
	})

	grpcLis, err := net.Listen("tcp", ":"+cfg.GRPCPort)
	if err != nil {
		log.Fatalf("gRPC listen: %v", err)
	}
	go func() {
		log.Printf("gRPC server listening on :%s", cfg.GRPCPort)
		if err := grpcSrv.Serve(grpcLis); err != nil {
			log.Fatalf("gRPC serve: %v", err)
		}
	}()

	log.Printf("Authentication Service listening on :%s", cfg.Port)
	log.Printf("Database connected")
	if rdb != nil {
		log.Printf("Redis connected")
	}
	if len(oauthProviders) > 0 {
		log.Printf("OAuth providers enabled: %d", len(oauthProviders))
	}
	if passkeySvc != nil {
		log.Printf("WebAuthn/Passkeys enabled")
	}
	log.Fatal(server.ListenAndServe())
}
