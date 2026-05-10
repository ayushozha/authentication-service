package grpc

import (
	"context"

	"github.com/Ayush10/authentication-service/internal/application"
	"github.com/Ayush10/authentication-service/internal/domain"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// AdminServer implements the AdminService gRPC service.
// All methods require the admin API key in metadata (enforced by interceptor).
type AdminServer struct {
	clients     *application.ClientService
	admins      *application.AdminService
	adminAPIKey string
}

func (s *AdminServer) CreateClient(ctx context.Context, req *CreateClientRequest) (*CreateClientResponse, error) {
	if err := s.authorize(ctx, application.AdminPermissionClientsCreate, "", true, "client", "", "admin.grpc.clients.create"); err != nil {
		return nil, err
	}
	if req.Name == "" {
		s.logAdminAction(ctx, "admin.grpc.clients.create", "client", "", "", codes.InvalidArgument, "name is required")
		return nil, status.Errorf(codes.InvalidArgument, "name is required")
	}
	if req.Slug == "" {
		s.logAdminAction(ctx, "admin.grpc.clients.create", "client", "", "", codes.InvalidArgument, "slug is required")
		return nil, status.Errorf(codes.InvalidArgument, "slug is required")
	}

	resp, err := s.clients.CreateClient(ctx, application.CreateClientRequest{
		Name:           req.Name,
		Slug:           req.Slug,
		AllowedOrigins: req.AllowedOrigins,
		WebhookURL:     req.WebhookURL,
	})
	if err != nil {
		grpcErr := domainToGRPCError(err)
		s.logAdminAction(ctx, "admin.grpc.clients.create", "client", "", "", codeFromError(grpcErr), err.Error())
		return nil, grpcErr
	}
	s.logAdminAction(ctx, "admin.grpc.clients.create", "client", resp.Client.ID, resp.Client.ID, codes.OK, "")

	return &CreateClientResponse{
		Client: clientToResponse(resp.Client),
		APIKey: resp.APIKey,
	}, nil
}

func (s *AdminServer) GetClient(ctx context.Context, req *GetClientRequest) (*ClientResponse, error) {
	if req.ClientID == "" {
		s.logAdminAction(ctx, "admin.grpc.clients.read", "client", "", "", codes.InvalidArgument, "client_id is required")
		return nil, status.Errorf(codes.InvalidArgument, "client_id is required")
	}
	if err := s.authorize(ctx, application.AdminPermissionClientsRead, req.ClientID, false, "client", req.ClientID, "admin.grpc.clients.read"); err != nil {
		return nil, err
	}

	client, err := s.clients.GetClient(ctx, req.ClientID)
	if err != nil {
		grpcErr := domainToGRPCError(err)
		s.logAdminAction(ctx, "admin.grpc.clients.read", "client", req.ClientID, req.ClientID, codeFromError(grpcErr), err.Error())
		return nil, grpcErr
	}
	if client == nil {
		s.logAdminAction(ctx, "admin.grpc.clients.read", "client", req.ClientID, req.ClientID, codes.NotFound, "client not found")
		return nil, status.Errorf(codes.NotFound, "client not found")
	}
	s.logAdminAction(ctx, "admin.grpc.clients.read", "client", req.ClientID, req.ClientID, codes.OK, "")

	return clientToResponse(client), nil
}

func (s *AdminServer) ListClients(ctx context.Context, req *ListClientsRequest) (*ListClientsResponse, error) {
	actor := adminActorFromContext(ctx)
	if err := s.authorize(ctx, application.AdminPermissionClientsRead, "", false, "client", "", "admin.grpc.clients.list"); err != nil {
		return nil, err
	}
	clients, err := s.clients.ListClients(ctx)
	if err != nil {
		grpcErr := domainToGRPCError(err)
		s.logAdminAction(ctx, "admin.grpc.clients.list", "client", "", "", codeFromError(grpcErr), err.Error())
		return nil, grpcErr
	}

	resp := &ListClientsResponse{
		Clients: make([]*ClientResponse, 0, len(clients)),
	}
	for _, c := range clients {
		if actor != nil && !actor.MatchesClient(c.ID) {
			continue
		}
		resp.Clients = append(resp.Clients, clientToResponse(c))
	}
	s.logAdminAction(ctx, "admin.grpc.clients.list", "client", "", "", codes.OK, "")

	return resp, nil
}

func (s *AdminServer) RotateJWTSecret(ctx context.Context, req *RotateJWTSecretRequest) (*ClientResponse, error) {
	if req.ClientID == "" {
		s.logAdminAction(ctx, "admin.grpc.clients.rotate_jwt", "client", "", "", codes.InvalidArgument, "client_id is required")
		return nil, status.Errorf(codes.InvalidArgument, "client_id is required")
	}
	if err := s.authorize(ctx, application.AdminPermissionClientsRotate, req.ClientID, false, "client", req.ClientID, "admin.grpc.clients.rotate_jwt"); err != nil {
		return nil, err
	}

	_, client, err := s.clients.RotateJWTSecret(ctx, req.ClientID)
	if err != nil {
		grpcErr := domainToGRPCError(err)
		s.logAdminAction(ctx, "admin.grpc.clients.rotate_jwt", "client", req.ClientID, req.ClientID, codeFromError(grpcErr), err.Error())
		return nil, grpcErr
	}
	s.logAdminAction(ctx, "admin.grpc.clients.rotate_jwt", "client", req.ClientID, req.ClientID, codes.OK, "")

	return clientToResponse(client), nil
}

func (s *AdminServer) RotateAPIKey(ctx context.Context, req *RotateAPIKeyRequest) (*RotateAPIKeyResponse, error) {
	if req.ClientID == "" {
		s.logAdminAction(ctx, "admin.grpc.clients.rotate_api_key", "client", "", "", codes.InvalidArgument, "client_id is required")
		return nil, status.Errorf(codes.InvalidArgument, "client_id is required")
	}
	if err := s.authorize(ctx, application.AdminPermissionClientsRotate, req.ClientID, false, "client", req.ClientID, "admin.grpc.clients.rotate_api_key"); err != nil {
		return nil, err
	}

	newKey, client, err := s.clients.RotateAPIKey(ctx, req.ClientID)
	if err != nil {
		grpcErr := domainToGRPCError(err)
		s.logAdminAction(ctx, "admin.grpc.clients.rotate_api_key", "client", req.ClientID, req.ClientID, codeFromError(grpcErr), err.Error())
		return nil, grpcErr
	}
	s.logAdminAction(ctx, "admin.grpc.clients.rotate_api_key", "client", req.ClientID, req.ClientID, codes.OK, "")

	return &RotateAPIKeyResponse{
		Client: clientToResponse(client),
		APIKey: newKey,
	}, nil
}

func (s *AdminServer) authorize(ctx context.Context, permission, targetClientID string, requireAllScope bool, targetType, targetID, eventType string) error {
	if s.admins == nil {
		return nil
	}
	if err := s.admins.Authorize(adminActorFromContext(ctx), permission, targetClientID, requireAllScope); err != nil {
		s.logAdminAction(ctx, eventType, targetType, targetID, targetClientID, codes.PermissionDenied, err.Error())
		return status.Errorf(codes.PermissionDenied, "forbidden")
	}
	return nil
}

func (s *AdminServer) logAdminAction(ctx context.Context, eventType, targetType, targetID, clientID string, code codes.Code, errMessage string) {
	if s.admins == nil {
		return
	}
	ip, ua := metadataFromContext(ctx)
	actor := adminActorFromContext(ctx)
	event := &domain.AuditEvent{
		ClientID:   clientID,
		EventType:  eventType,
		TargetType: targetType,
		TargetID:   targetID,
		RequestID:  requestIDFromContext(ctx),
		IPAddress:  ip,
		UserAgent:  ua,
		Metadata: map[string]interface{}{
			"transport": "grpc",
			"grpc_code": code.String(),
		},
	}
	if errMessage != "" {
		event.Metadata["error"] = errMessage
	}
	if actor != nil {
		event.ActorType = actor.Type
		event.ActorID = actor.ID
		event.ActorEmail = actor.Email
	} else {
		event.ActorType = "unknown"
	}
	s.admins.LogAdminAction(ctx, event)
}

func codeFromError(err error) codes.Code {
	if st, ok := status.FromError(err); ok {
		return st.Code()
	}
	return codes.Unknown
}

// --- Service descriptor for manual gRPC registration ---

// adminServiceInterface is the interface type required by grpc.ServiceDesc.HandlerType.
type adminServiceInterface interface {
	CreateClient(context.Context, *CreateClientRequest) (*CreateClientResponse, error)
	GetClient(context.Context, *GetClientRequest) (*ClientResponse, error)
	ListClients(context.Context, *ListClientsRequest) (*ListClientsResponse, error)
	RotateJWTSecret(context.Context, *RotateJWTSecretRequest) (*ClientResponse, error)
	RotateAPIKey(context.Context, *RotateAPIKeyRequest) (*RotateAPIKeyResponse, error)
}

var adminServiceDesc = grpc.ServiceDesc{
	ServiceName: "auth.v1.AdminService",
	HandlerType: (*adminServiceInterface)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CreateClient",
			Handler:    adminHandler_CreateClient,
		},
		{
			MethodName: "GetClient",
			Handler:    adminHandler_GetClient,
		},
		{
			MethodName: "ListClients",
			Handler:    adminHandler_ListClients,
		},
		{
			MethodName: "RotateJWTSecret",
			Handler:    adminHandler_RotateJWTSecret,
		},
		{
			MethodName: "RotateAPIKey",
			Handler:    adminHandler_RotateAPIKey,
		},
	},
	Streams: []grpc.StreamDesc{},
}

func adminHandler_CreateClient(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	req := new(CreateClientRequest)
	if err := dec(req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(*AdminServer).CreateClient(ctx, req)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/auth.v1.AdminService/CreateClient",
	}
	handler := func(ctx context.Context, r interface{}) (interface{}, error) {
		return srv.(*AdminServer).CreateClient(ctx, r.(*CreateClientRequest))
	}
	return interceptor(ctx, req, info, handler)
}

func adminHandler_GetClient(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	req := new(GetClientRequest)
	if err := dec(req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(*AdminServer).GetClient(ctx, req)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/auth.v1.AdminService/GetClient",
	}
	handler := func(ctx context.Context, r interface{}) (interface{}, error) {
		return srv.(*AdminServer).GetClient(ctx, r.(*GetClientRequest))
	}
	return interceptor(ctx, req, info, handler)
}

func adminHandler_ListClients(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	req := new(ListClientsRequest)
	if err := dec(req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(*AdminServer).ListClients(ctx, req)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/auth.v1.AdminService/ListClients",
	}
	handler := func(ctx context.Context, r interface{}) (interface{}, error) {
		return srv.(*AdminServer).ListClients(ctx, r.(*ListClientsRequest))
	}
	return interceptor(ctx, req, info, handler)
}

func adminHandler_RotateJWTSecret(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	req := new(RotateJWTSecretRequest)
	if err := dec(req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(*AdminServer).RotateJWTSecret(ctx, req)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/auth.v1.AdminService/RotateJWTSecret",
	}
	handler := func(ctx context.Context, r interface{}) (interface{}, error) {
		return srv.(*AdminServer).RotateJWTSecret(ctx, r.(*RotateJWTSecretRequest))
	}
	return interceptor(ctx, req, info, handler)
}

func adminHandler_RotateAPIKey(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	req := new(RotateAPIKeyRequest)
	if err := dec(req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(*AdminServer).RotateAPIKey(ctx, req)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/auth.v1.AdminService/RotateAPIKey",
	}
	handler := func(ctx context.Context, r interface{}) (interface{}, error) {
		return srv.(*AdminServer).RotateAPIKey(ctx, r.(*RotateAPIKeyRequest))
	}
	return interceptor(ctx, req, info, handler)
}
