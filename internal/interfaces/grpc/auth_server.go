package grpc

import (
	"context"
	"time"

	"github.com/Ayush10/authentication-service/internal/application"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// AuthServer implements the AuthService gRPC service.
type AuthServer struct {
	auth       *application.AuthService
	verify     *application.EmailVerifyService
	pwReset    *application.PasswordResetService
	magic      *application.MagicLinkService
	clients    *application.ClientService
	bcryptCost int
	accessTTL  time.Duration
	refreshTTL time.Duration
	baseURL    string
}

func (s *AuthServer) Signup(ctx context.Context, req *SignupRequest) (*AuthResponse, error) {
	if req.APIKey == "" {
		return nil, status.Errorf(codes.InvalidArgument, "api_key is required")
	}
	client, err := s.clients.GetClientByAPIKey(ctx, req.APIKey)
	if err != nil {
		return nil, domainToGRPCError(err)
	}

	ip, ua := req.IP, req.UserAgent
	if ip == "" || ua == "" {
		mdIP, mdUA := metadataFromContext(ctx)
		if ip == "" {
			ip = mdIP
		}
		if ua == "" {
			ua = mdUA
		}
	}

	resp, err := s.auth.Signup(ctx, client, application.SignupRequest{
		Email:       req.Email,
		Password:    req.Password,
		DisplayName: req.DisplayName,
	}, ip, ua, s.bcryptCost, s.accessTTL, s.refreshTTL)
	if err != nil {
		return nil, domainToGRPCError(err)
	}

	return &AuthResponse{
		AccessToken: resp.AccessToken,
		TokenType:   resp.TokenType,
		ExpiresIn:   int32(resp.ExpiresIn),
		User:        userToResponse(resp.User),
	}, nil
}

func (s *AuthServer) Login(ctx context.Context, req *LoginRequest) (*AuthResponse, error) {
	if req.APIKey == "" {
		return nil, status.Errorf(codes.InvalidArgument, "api_key is required")
	}
	client, err := s.clients.GetClientByAPIKey(ctx, req.APIKey)
	if err != nil {
		return nil, domainToGRPCError(err)
	}

	ip, ua := req.IP, req.UserAgent
	if ip == "" || ua == "" {
		mdIP, mdUA := metadataFromContext(ctx)
		if ip == "" {
			ip = mdIP
		}
		if ua == "" {
			ua = mdUA
		}
	}

	resp, refreshToken, err := s.auth.Login(ctx, client, application.LoginRequest{
		Email:    req.Email,
		Password: req.Password,
	}, ip, ua, s.accessTTL, s.refreshTTL)
	if err != nil {
		return nil, domainToGRPCError(err)
	}

	return &AuthResponse{
		AccessToken:      resp.AccessToken,
		RefreshToken:     refreshToken,
		TokenType:        resp.TokenType,
		ExpiresIn:        int32(resp.ExpiresIn),
		User:             userToResponse(resp.User),
		Requires2FA:      resp.Requires2FA,
		TwoFactorToken:   resp.TwoFAToken,
		TwoFactorMethods: resp.TwoFAMethods,
	}, nil
}

func (s *AuthServer) RefreshToken(ctx context.Context, req *RefreshTokenRequest) (*AuthResponse, error) {
	if req.APIKey == "" {
		return nil, status.Errorf(codes.InvalidArgument, "api_key is required")
	}
	client, err := s.clients.GetClientByAPIKey(ctx, req.APIKey)
	if err != nil {
		return nil, domainToGRPCError(err)
	}

	ip, ua := req.IP, req.UserAgent
	if ip == "" || ua == "" {
		mdIP, mdUA := metadataFromContext(ctx)
		if ip == "" {
			ip = mdIP
		}
		if ua == "" {
			ua = mdUA
		}
	}

	resp, newRefreshToken, err := s.auth.Refresh(ctx, client, req.RefreshToken, ip, ua, s.accessTTL, s.refreshTTL)
	if err != nil {
		return nil, domainToGRPCError(err)
	}

	return &AuthResponse{
		AccessToken:  resp.AccessToken,
		RefreshToken: newRefreshToken,
		TokenType:    resp.TokenType,
		ExpiresIn:    int32(resp.ExpiresIn),
		User:         userToResponse(resp.User),
	}, nil
}

func (s *AuthServer) Logout(ctx context.Context, req *LogoutRequest) (*Empty, error) {
	if err := s.auth.Logout(ctx, req.RefreshToken); err != nil {
		return nil, domainToGRPCError(err)
	}
	return &Empty{}, nil
}

func (s *AuthServer) GetUser(ctx context.Context, req *GetUserRequest) (*UserResponse, error) {
	if req.UserID == "" {
		return nil, status.Errorf(codes.InvalidArgument, "user_id is required")
	}
	user, err := s.auth.GetUser(ctx, req.UserID)
	if err != nil {
		return nil, domainToGRPCError(err)
	}
	if user == nil {
		return nil, status.Errorf(codes.NotFound, "user not found")
	}
	return userToResponse(user), nil
}

func (s *AuthServer) UpdateUser(ctx context.Context, req *UpdateUserRequest) (*UserResponse, error) {
	if req.UserID == "" {
		return nil, status.Errorf(codes.InvalidArgument, "user_id is required")
	}
	user, err := s.auth.UpdateProfile(ctx, req.UserID, application.UpdateProfileRequest{
		DisplayName: req.DisplayName,
		Timezone:    req.Timezone,
	})
	if err != nil {
		return nil, domainToGRPCError(err)
	}
	return userToResponse(user), nil
}

func (s *AuthServer) ChangePassword(ctx context.Context, req *ChangePasswordRequest) (*Empty, error) {
	if req.APIKey == "" {
		return nil, status.Errorf(codes.InvalidArgument, "api_key is required")
	}
	if req.UserID == "" {
		return nil, status.Errorf(codes.InvalidArgument, "user_id is required")
	}
	client, err := s.clients.GetClientByAPIKey(ctx, req.APIKey)
	if err != nil {
		return nil, domainToGRPCError(err)
	}

	ip, ua := req.IP, req.UserAgent
	if ip == "" || ua == "" {
		mdIP, mdUA := metadataFromContext(ctx)
		if ip == "" {
			ip = mdIP
		}
		if ua == "" {
			ua = mdUA
		}
	}

	err = s.auth.ChangePassword(ctx, client, req.UserID, application.ChangePasswordRequest{
		OldPassword: req.OldPassword,
		NewPassword: req.NewPassword,
	}, ip, ua, s.bcryptCost)
	if err != nil {
		return nil, domainToGRPCError(err)
	}
	return &Empty{}, nil
}

func (s *AuthServer) VerifyEmail(ctx context.Context, req *VerifyEmailRequest) (*Empty, error) {
	if req.Token == "" {
		return nil, status.Errorf(codes.InvalidArgument, "token is required")
	}
	if err := s.verify.VerifyEmail(ctx, req.Token); err != nil {
		return nil, domainToGRPCError(err)
	}
	return &Empty{}, nil
}

func (s *AuthServer) ResendVerification(ctx context.Context, req *ResendVerificationRequest) (*Empty, error) {
	if req.UserID == "" {
		return nil, status.Errorf(codes.InvalidArgument, "user_id is required")
	}
	baseURL := req.BaseURL
	if baseURL == "" {
		baseURL = s.baseURL
	}
	if err := s.verify.ResendVerification(ctx, req.UserID, baseURL); err != nil {
		return nil, domainToGRPCError(err)
	}
	return &Empty{}, nil
}

func (s *AuthServer) ForgotPassword(ctx context.Context, req *ForgotPasswordRequest) (*Empty, error) {
	if req.Email == "" {
		return nil, status.Errorf(codes.InvalidArgument, "email is required")
	}
	baseURL := req.BaseURL
	if baseURL == "" {
		baseURL = s.baseURL
	}
	if err := s.pwReset.ForgotPassword(ctx, req.ClientID, req.Email, baseURL); err != nil {
		return nil, domainToGRPCError(err)
	}
	return &Empty{}, nil
}

func (s *AuthServer) ResetPassword(ctx context.Context, req *ResetPasswordRequest) (*Empty, error) {
	if req.Token == "" {
		return nil, status.Errorf(codes.InvalidArgument, "token is required")
	}
	if err := s.pwReset.ResetPassword(ctx, req.Token, req.NewPassword, s.bcryptCost); err != nil {
		return nil, domainToGRPCError(err)
	}
	return &Empty{}, nil
}

func (s *AuthServer) SendMagicLink(ctx context.Context, req *SendMagicLinkRequest) (*Empty, error) {
	if req.APIKey == "" {
		return nil, status.Errorf(codes.InvalidArgument, "api_key is required")
	}
	client, err := s.clients.GetClientByAPIKey(ctx, req.APIKey)
	if err != nil {
		return nil, domainToGRPCError(err)
	}

	ip, ua := req.IP, req.UserAgent
	if ip == "" || ua == "" {
		mdIP, mdUA := metadataFromContext(ctx)
		if ip == "" {
			ip = mdIP
		}
		if ua == "" {
			ua = mdUA
		}
	}

	baseURL := req.BaseURL
	if baseURL == "" {
		baseURL = s.baseURL
	}

	if err := s.magic.SendMagicLink(ctx, client, req.Email, baseURL, ip, ua); err != nil {
		return nil, domainToGRPCError(err)
	}
	return &Empty{}, nil
}

func (s *AuthServer) VerifyMagicLink(ctx context.Context, req *VerifyMagicLinkRequest) (*AuthResponse, error) {
	if req.APIKey == "" {
		return nil, status.Errorf(codes.InvalidArgument, "api_key is required")
	}
	client, err := s.clients.GetClientByAPIKey(ctx, req.APIKey)
	if err != nil {
		return nil, domainToGRPCError(err)
	}

	ip, ua := req.IP, req.UserAgent
	if ip == "" || ua == "" {
		mdIP, mdUA := metadataFromContext(ctx)
		if ip == "" {
			ip = mdIP
		}
		if ua == "" {
			ua = mdUA
		}
	}

	resp, refreshToken, err := s.magic.VerifyMagicLink(ctx, client, req.Token, ip, ua, s.accessTTL, s.refreshTTL)
	if err != nil {
		return nil, domainToGRPCError(err)
	}

	return &AuthResponse{
		AccessToken:  resp.AccessToken,
		RefreshToken: refreshToken,
		TokenType:    resp.TokenType,
		ExpiresIn:    int32(resp.ExpiresIn),
		User:         userToResponse(resp.User),
	}, nil
}

// --- Service descriptor for manual gRPC registration ---

var authServiceDesc = grpc.ServiceDesc{
	ServiceName: "auth.v1.AuthService",
	HandlerType: (*AuthServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Signup",
			Handler:    authHandler_Signup,
		},
		{
			MethodName: "Login",
			Handler:    authHandler_Login,
		},
		{
			MethodName: "RefreshToken",
			Handler:    authHandler_RefreshToken,
		},
		{
			MethodName: "Logout",
			Handler:    authHandler_Logout,
		},
		{
			MethodName: "GetUser",
			Handler:    authHandler_GetUser,
		},
		{
			MethodName: "UpdateUser",
			Handler:    authHandler_UpdateUser,
		},
		{
			MethodName: "ChangePassword",
			Handler:    authHandler_ChangePassword,
		},
		{
			MethodName: "VerifyEmail",
			Handler:    authHandler_VerifyEmail,
		},
		{
			MethodName: "ResendVerification",
			Handler:    authHandler_ResendVerification,
		},
		{
			MethodName: "ForgotPassword",
			Handler:    authHandler_ForgotPassword,
		},
		{
			MethodName: "ResetPassword",
			Handler:    authHandler_ResetPassword,
		},
		{
			MethodName: "SendMagicLink",
			Handler:    authHandler_SendMagicLink,
		},
		{
			MethodName: "VerifyMagicLink",
			Handler:    authHandler_VerifyMagicLink,
		},
	},
	Streams: []grpc.StreamDesc{},
}

func authHandler_Signup(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	req := new(SignupRequest)
	if err := dec(req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(*AuthServer).Signup(ctx, req)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/auth.v1.AuthService/Signup",
	}
	handler := func(ctx context.Context, r interface{}) (interface{}, error) {
		return srv.(*AuthServer).Signup(ctx, r.(*SignupRequest))
	}
	return interceptor(ctx, req, info, handler)
}

func authHandler_Login(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	req := new(LoginRequest)
	if err := dec(req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(*AuthServer).Login(ctx, req)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/auth.v1.AuthService/Login",
	}
	handler := func(ctx context.Context, r interface{}) (interface{}, error) {
		return srv.(*AuthServer).Login(ctx, r.(*LoginRequest))
	}
	return interceptor(ctx, req, info, handler)
}

func authHandler_RefreshToken(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	req := new(RefreshTokenRequest)
	if err := dec(req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(*AuthServer).RefreshToken(ctx, req)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/auth.v1.AuthService/RefreshToken",
	}
	handler := func(ctx context.Context, r interface{}) (interface{}, error) {
		return srv.(*AuthServer).RefreshToken(ctx, r.(*RefreshTokenRequest))
	}
	return interceptor(ctx, req, info, handler)
}

func authHandler_Logout(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	req := new(LogoutRequest)
	if err := dec(req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(*AuthServer).Logout(ctx, req)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/auth.v1.AuthService/Logout",
	}
	handler := func(ctx context.Context, r interface{}) (interface{}, error) {
		return srv.(*AuthServer).Logout(ctx, r.(*LogoutRequest))
	}
	return interceptor(ctx, req, info, handler)
}

func authHandler_GetUser(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	req := new(GetUserRequest)
	if err := dec(req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(*AuthServer).GetUser(ctx, req)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/auth.v1.AuthService/GetUser",
	}
	handler := func(ctx context.Context, r interface{}) (interface{}, error) {
		return srv.(*AuthServer).GetUser(ctx, r.(*GetUserRequest))
	}
	return interceptor(ctx, req, info, handler)
}

func authHandler_UpdateUser(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	req := new(UpdateUserRequest)
	if err := dec(req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(*AuthServer).UpdateUser(ctx, req)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/auth.v1.AuthService/UpdateUser",
	}
	handler := func(ctx context.Context, r interface{}) (interface{}, error) {
		return srv.(*AuthServer).UpdateUser(ctx, r.(*UpdateUserRequest))
	}
	return interceptor(ctx, req, info, handler)
}

func authHandler_ChangePassword(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	req := new(ChangePasswordRequest)
	if err := dec(req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(*AuthServer).ChangePassword(ctx, req)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/auth.v1.AuthService/ChangePassword",
	}
	handler := func(ctx context.Context, r interface{}) (interface{}, error) {
		return srv.(*AuthServer).ChangePassword(ctx, r.(*ChangePasswordRequest))
	}
	return interceptor(ctx, req, info, handler)
}

func authHandler_VerifyEmail(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	req := new(VerifyEmailRequest)
	if err := dec(req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(*AuthServer).VerifyEmail(ctx, req)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/auth.v1.AuthService/VerifyEmail",
	}
	handler := func(ctx context.Context, r interface{}) (interface{}, error) {
		return srv.(*AuthServer).VerifyEmail(ctx, r.(*VerifyEmailRequest))
	}
	return interceptor(ctx, req, info, handler)
}

func authHandler_ResendVerification(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	req := new(ResendVerificationRequest)
	if err := dec(req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(*AuthServer).ResendVerification(ctx, req)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/auth.v1.AuthService/ResendVerification",
	}
	handler := func(ctx context.Context, r interface{}) (interface{}, error) {
		return srv.(*AuthServer).ResendVerification(ctx, r.(*ResendVerificationRequest))
	}
	return interceptor(ctx, req, info, handler)
}

func authHandler_ForgotPassword(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	req := new(ForgotPasswordRequest)
	if err := dec(req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(*AuthServer).ForgotPassword(ctx, req)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/auth.v1.AuthService/ForgotPassword",
	}
	handler := func(ctx context.Context, r interface{}) (interface{}, error) {
		return srv.(*AuthServer).ForgotPassword(ctx, r.(*ForgotPasswordRequest))
	}
	return interceptor(ctx, req, info, handler)
}

func authHandler_ResetPassword(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	req := new(ResetPasswordRequest)
	if err := dec(req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(*AuthServer).ResetPassword(ctx, req)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/auth.v1.AuthService/ResetPassword",
	}
	handler := func(ctx context.Context, r interface{}) (interface{}, error) {
		return srv.(*AuthServer).ResetPassword(ctx, r.(*ResetPasswordRequest))
	}
	return interceptor(ctx, req, info, handler)
}

func authHandler_SendMagicLink(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	req := new(SendMagicLinkRequest)
	if err := dec(req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(*AuthServer).SendMagicLink(ctx, req)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/auth.v1.AuthService/SendMagicLink",
	}
	handler := func(ctx context.Context, r interface{}) (interface{}, error) {
		return srv.(*AuthServer).SendMagicLink(ctx, r.(*SendMagicLinkRequest))
	}
	return interceptor(ctx, req, info, handler)
}

func authHandler_VerifyMagicLink(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	req := new(VerifyMagicLinkRequest)
	if err := dec(req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(*AuthServer).VerifyMagicLink(ctx, req)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/auth.v1.AuthService/VerifyMagicLink",
	}
	handler := func(ctx context.Context, r interface{}) (interface{}, error) {
		return srv.(*AuthServer).VerifyMagicLink(ctx, r.(*VerifyMagicLinkRequest))
	}
	return interceptor(ctx, req, info, handler)
}
