package rest

import (
	"context"
	"net/http"
	"time"

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
	adminSvc *application.AdminService,
	clientSvc *application.ClientService,
	auditSvc *application.AuditService,
	orgSvc *application.OrganizationService,
	adaptiveSvc *application.AdaptiveSecurityService,
	m2mSvc *application.M2MService,
	ssoSvc *application.EnterpriseSSOService,
	scimSvc *application.SCIMService,
	enterpriseOnboardingSvc *application.EnterpriseOnboardingService,
	oidcSvc *application.OIDCService,
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
	adminMw := RequireAdminAuth(adminSvc, adminAPIKey)

	// API key protected auth routes.
	authMux := http.NewServeMux()

	// Register routes that require API key (and optional bearer user auth).
	authHandler := NewAuthHandler(authSvc, cfg)
	authHandler.RegisterRoutes(authMux, authMw)
	uiConfigHandler := NewUIConfigHandler(cfg)
	uiConfigHandler.RegisterRoutes(authMux)

	verifyHandler := NewVerifyHandler(verifySvc, resetSvc, cfg)
	verifyHandler.RegisterAPIKeyRoutes(authMux)
	verifyHandler.RegisterProtectedRoutes(authMux, authMw)

	magicHandler := NewMagicLinkHandler(magicSvc, cfg)
	magicHandler.RegisterSendRoute(authMux)

	totpHandler := NewTOTPHandler(totpSvc, cfg)
	totpHandler.RegisterRoutes(authMux, authMw)

	adaptiveHandler := NewAdaptiveSecurityHandler(adaptiveSvc, cfg)
	adaptiveHandler.RegisterRoutes(authMux, authMw)

	if oauthSvc != nil && oauthProviders != nil {
		oauthHandler := NewOAuthHandler(oauthSvc, oauthProviders, cfg)
		oauthHandler.RegisterBeginRoutes(authMux)
		oauthHandler.RegisterCallbackRoutes(mux)
	}

	if passkeySvc != nil {
		passkeyHandler := NewPasskeyHandler(passkeySvc, cfg)
		passkeyHandler.RegisterRoutes(authMux, authMw)
	}
	if orgSvc != nil {
		orgHandler := NewOrganizationHandler(orgSvc, adaptiveSvc, cfg)
		orgHandler.RegisterRoutes(authMux, authMw)
	}
	if enterpriseOnboardingSvc != nil {
		enterpriseOnboardingHandler := NewEnterpriseOnboardingHandler(enterpriseOnboardingSvc, cfg)
		enterpriseOnboardingHandler.RegisterRoutes(authMux, authMw)
	}
	m2mHandler := NewM2MHandler(m2mSvc, adaptiveSvc, cfg)
	m2mHandler.RegisterOAuthRoutes(mux)
	oidcHandler := NewOIDCHandler(oidcSvc, authSvc, m2mSvc, cfg)
	oidcHandler.RegisterRoutes(mux)
	ssoHandler := NewEnterpriseSSOHandler(ssoSvc, cfg)
	if ssoSvc != nil {
		ssoHandler.RegisterAuthRoutes(authMux, mux)
	}
	scimHandler := NewSCIMHandler(scimSvc, cfg)
	if scimSvc != nil {
		scimHandler.RegisterRoutes(mux)
	}

	// Public auth routes (no API key required).
	verifyHandler.RegisterPublicRoutes(mux)
	magicHandler.RegisterVerifyPublicRoute(mux)
	RegisterRedirectCodeRoute(mux, cfg)
	adminHandler := NewAdminHandler(adminSvc, cfg)
	adminHandler.RegisterAuthRoutes(mux)

	// Mount auth routes under API key middleware
	mux.Handle("/api/auth/", apiKeyMw(authMux))

	// Admin routes (protected by admin key)
	adaptiveHandler.RegisterAdminRoutes(mux, adminMw)
	clientHandler := NewClientHandler(clientSvc, adaptiveSvc, m2mHandler, ssoHandler, scimHandler)
	clientHandler.RegisterRoutes(mux, adminMw)
	adminHandler.RegisterUserRoutes(mux, adminMw)
	if auditSvc != nil {
		auditHandler := NewAuditHandler(auditSvc, adaptiveSvc)
		auditHandler.RegisterRoutes(mux, adminMw)
	}

	// API documentation
	mux.HandleFunc("/docs", DocsUIHandler)
	mux.HandleFunc("/docs/", DocsUIHandler)
	mux.HandleFunc("/docs/openapi.yaml", DocsSpecHandler)

	// Health check
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		application.Metrics().WritePrometheus(w)
	})
	mux.Handle("/api/admin/metrics", adminMw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		application.Metrics().WritePrometheus(w)
	})))

	// JWKS endpoint for RS256 token validation.
	mux.HandleFunc("/.well-known/jwks.json", CORSHandler(cfg.AllowOrigin, MethodCheck(http.MethodGet, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=300, stale-while-revalidate=60")
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		apiKey := r.Header.Get("X-API-Key")
		if apiKey != "" {
			client, err := clientSvc.GetClientByAPIKey(ctx, apiKey)
			if err != nil || client == nil {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid client"})
				return
			}
			jwks, err := application.ClientJWKS(ctx, client.ID)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not load jwks"})
				return
			}
			writeJSON(w, http.StatusOK, jwks)
			return
		}

		clientID := r.URL.Query().Get("client_id")
		if clientID != "" {
			client, err := clientSvc.GetClient(ctx, clientID)
			if err != nil || client == nil {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid client"})
				return
			}
			jwks, err := application.ClientJWKS(ctx, client.ID)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not load jwks"})
				return
			}
			writeJSON(w, http.StatusOK, jwks)
			return
		}

		jwks, err := application.JWKS(ctx)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not load jwks"})
			return
		}
		writeJSON(w, http.StatusOK, jwks)
	})))

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
