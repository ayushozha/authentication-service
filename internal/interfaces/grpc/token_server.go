package grpc

import (
	"context"

	"github.com/Ayush10/authentication-service/internal/application"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TokenServer implements the TokenService gRPC service.
// It provides token validation for other microservices.
type TokenServer struct {
	auth    *application.AuthService
	clients *application.ClientService
}

func (s *TokenServer) ValidateToken(ctx context.Context, req *ValidateTokenRequest) (*ValidateTokenResponse, error) {
	if req.AccessToken == "" {
		return nil, status.Errorf(codes.InvalidArgument, "access_token is required")
	}
	if req.APIKey == "" {
		return nil, status.Errorf(codes.InvalidArgument, "api_key is required")
	}

	client, err := s.clients.GetClientByAPIKey(ctx, req.APIKey)
	if err != nil {
		return &ValidateTokenResponse{
			Valid: false,
			Error: "invalid API key",
		}, nil
	}

	claims, err := application.ValidateAccessToken(ctx, client, req.AccessToken)
	if err != nil {
		return &ValidateTokenResponse{
			Valid: false,
			Error: err.Error(),
		}, nil
	}

	return &ValidateTokenResponse{
		Valid:         true,
		UserID:        claims.Subject,
		Email:         claims.Email,
		Role:          claims.Role,
		EmailVerified: claims.EmailVerified,
		ClientID:      claims.ClientID,
	}, nil
}

// --- Service descriptor for manual gRPC registration ---

// tokenServiceInterface is the interface type required by grpc.ServiceDesc.HandlerType.
type tokenServiceInterface interface {
	ValidateToken(context.Context, *ValidateTokenRequest) (*ValidateTokenResponse, error)
}

var tokenServiceDesc = grpc.ServiceDesc{
	ServiceName: "auth.v1.TokenService",
	HandlerType: (*tokenServiceInterface)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "ValidateToken",
			Handler:    tokenHandler_ValidateToken,
		},
	},
	Streams: []grpc.StreamDesc{},
}

func tokenHandler_ValidateToken(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	req := new(ValidateTokenRequest)
	if err := dec(req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(*TokenServer).ValidateToken(ctx, req)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/auth.v1.TokenService/ValidateToken",
	}
	handler := func(ctx context.Context, r interface{}) (interface{}, error) {
		return srv.(*TokenServer).ValidateToken(ctx, r.(*ValidateTokenRequest))
	}
	return interceptor(ctx, req, info, handler)
}
