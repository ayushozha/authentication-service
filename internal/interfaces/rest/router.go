package rest

import (
	"net/http"

	"github.com/Ayush10/authentication-service/internal/application"
)

type Router struct {
	mux *http.ServeMux
}

func NewRouter(
	authSvc *application.AuthService,
	verifySvc *application.EmailVerifyService,
	resetSvc *application.PasswordResetService,
	magicSvc *application.MagicLinkService,
	totpSvc *application.TOTPService,
	oauthSvc *application.OAuthService,
	passkeySvc *application.PasskeyService,
	clientSvc *application.ClientService,
	oauthProviders map[string]*application.OAuthProviderConfig,
	cfg *HandlerConfig,
	adminAPIKey string,
	serveFrontend bool,
	publicDir string,
) *Router {
	mux := http.NewServeMux()

	// API key middleware for auth endpoints
	apiKeyMw := RequireAPIKey(clientSvc)
	authMw := RequireUserAuth(clientSvc)
	adminMw := RequireAdminKey(adminAPIKey)

	// Wrap all auth endpoints with API key middleware
	authMux := http.NewServeMux()

	// Register auth handlers
	authHandler := NewAuthHandler(authSvc, cfg)
	authHandler.RegisterRoutes(authMux, authMw)

	verifyHandler := NewVerifyHandler(verifySvc, resetSvc, cfg)
	verifyHandler.RegisterRoutes(authMux, authMw)

	magicHandler := NewMagicLinkHandler(magicSvc, cfg)
	magicHandler.RegisterRoutes(authMux)

	totpHandler := NewTOTPHandler(totpSvc, cfg)
	totpHandler.RegisterRoutes(authMux, authMw)

	if oauthSvc != nil && oauthProviders != nil {
		oauthHandler := NewOAuthHandler(oauthSvc, oauthProviders, cfg)
		oauthHandler.RegisterRoutes(authMux)
	}

	if passkeySvc != nil {
		passkeyHandler := NewPasskeyHandler(passkeySvc, cfg)
		passkeyHandler.RegisterRoutes(authMux, authMw)
	}

	// Mount auth routes under API key middleware
	mux.Handle("/api/auth/", apiKeyMw(authMux))

	// Admin routes (protected by admin key)
	clientHandler := NewClientHandler(clientSvc)
	clientHandler.RegisterRoutes(mux, adminMw)

	// Health check
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// Static files (optional frontend)
	if serveFrontend && publicDir != "" {
		fileServer := http.FileServer(http.Dir(publicDir))
		mux.Handle("/", fileServer)
	}

	return &Router{mux: mux}
}

func (r *Router) Handler() http.Handler {
	return SecureHeaders(LogRequests(r.mux))
}
