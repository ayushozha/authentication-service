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

	// Redis (optional)
	rdb, err := redisclient.NewClient(cfg.RedisURL, cfg.RedisPrefix)
	if err != nil {
		log.Printf("WARNING: Redis unavailable: %v", err)
	}

	// Repositories
	clientRepo := postgres.NewClientRepo(db)
	userRepo := postgres.NewUserRepo(db)
	sessionRepo := postgres.NewSessionRepo(db)
	oauthRepo := postgres.NewOAuthRepo(db)
	webauthnRepo := postgres.NewWebAuthnRepo(db)
	tokenRepo := postgres.NewTokenRepo(db)
	auditRepo := postgres.NewAuditRepo(db)
	signingKeyRepo := postgres.NewSigningKeyRepo(db)
	application.SetSigningKeyRepository(signingKeyRepo)

	// Rate limiter
	rl := redisclient.NewRateLimiter(rdb)

	// Email client
	var mailer application.EmailSender
	resendClient := email.NewResendClient(cfg.ResendAPIKey, cfg.EmailFrom)
	if resendClient != nil {
		mailer = resendClient
	} else {
		log.Printf("WARNING: RESEND_API_KEY not set, email sending disabled")
	}

	// Application services
	clientSvc := application.NewClientService(clientRepo)
	authSvc := application.NewAuthService(userRepo, sessionRepo, rdb, auditRepo, rl)
	verifySvc := application.NewEmailVerifyService(userRepo, tokenRepo, mailer)
	resetSvc := application.NewPasswordResetService(userRepo, tokenRepo, sessionRepo, mailer)
	magicSvc := application.NewMagicLinkService(clientRepo, userRepo, sessionRepo, rdb, mailer, auditRepo, rl)
	totpSvc := application.NewTOTPService(userRepo, sessionRepo, rdb, auditRepo)
	oauthSvc := application.NewOAuthService(userRepo, clientRepo, oauthRepo, sessionRepo, rdb, auditRepo)
	auditSvc := application.NewAuditService(auditRepo)

	// Wire signup email hook
	verifySvc.WireSignupHook(cfg.BaseURL)

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
		userRepo, webauthnRepo, sessionRepo, rdb, auditRepo,
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
		oauthSvc, passkeySvc, clientSvc, auditSvc,
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
