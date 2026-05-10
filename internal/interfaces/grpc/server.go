package grpc

import (
	"net"
	"time"

	"github.com/Ayush10/authentication-service/internal/application"
	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/reflection"
)

// Server wraps a gRPC server with all registered authentication services.
type Server struct {
	gs    *grpc.Server
	auth  *AuthServer
	token *TokenServer
	admin *AdminServer
}

// Config holds the dependencies required to create the gRPC server.
type Config struct {
	AuthService          *application.AuthService
	EmailVerifyService   *application.EmailVerifyService
	PasswordResetService *application.PasswordResetService
	MagicLinkService     *application.MagicLinkService
	ClientService        *application.ClientService
	AdminService         *application.AdminService
	AdminAPIKey          string
	BcryptCost           int
	AccessTTL            time.Duration
	RefreshTTL           time.Duration
	BaseURL              string
}

func init() {
	// Register the JSON codec so gRPC can serialize/deserialize our plain Go structs.
	encoding.RegisterCodec(JSONCodec{})
}

// NewServer creates a new gRPC server with all authentication services registered.
func NewServer(cfg Config) *Server {
	gs := grpc.NewServer(
		grpc.UnaryInterceptor(chainUnaryInterceptors(
			loggingInterceptor,
			recoveryInterceptor,
			adminAuthInterceptor(cfg.AdminService, cfg.AdminAPIKey),
		)),
	)

	auth := &AuthServer{
		auth:       cfg.AuthService,
		verify:     cfg.EmailVerifyService,
		pwReset:    cfg.PasswordResetService,
		magic:      cfg.MagicLinkService,
		clients:    cfg.ClientService,
		bcryptCost: cfg.BcryptCost,
		accessTTL:  cfg.AccessTTL,
		refreshTTL: cfg.RefreshTTL,
		baseURL:    cfg.BaseURL,
	}

	token := &TokenServer{
		auth:    cfg.AuthService,
		clients: cfg.ClientService,
	}

	admin := &AdminServer{
		clients:     cfg.ClientService,
		admins:      cfg.AdminService,
		adminAPIKey: cfg.AdminAPIKey,
	}

	gs.RegisterService(&authServiceDesc, auth)
	gs.RegisterService(&tokenServiceDesc, token)
	gs.RegisterService(&adminServiceDesc, admin)
	reflection.Register(gs)

	return &Server{gs: gs, auth: auth, token: token, admin: admin}
}

// Serve starts the gRPC server on the given listener.
func (s *Server) Serve(lis net.Listener) error {
	return s.gs.Serve(lis)
}

// GracefulStop gracefully stops the gRPC server.
func (s *Server) GracefulStop() {
	s.gs.GracefulStop()
}

// GetGRPCServer returns the underlying grpc.Server for advanced configuration.
func (s *Server) GetGRPCServer() *grpc.Server {
	return s.gs
}
