package grpc

import (
	"context"

	"github.com/Ayush10/authentication-service/internal/application"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// AdminServer implements the AdminService gRPC service.
// All methods require the admin API key in metadata (enforced by interceptor).
type AdminServer struct {
	clients     *application.ClientService
	adminAPIKey string
}

func (s *AdminServer) CreateClient(ctx context.Context, req *CreateClientRequest) (*CreateClientResponse, error) {
	if req.Name == "" {
		return nil, status.Errorf(codes.InvalidArgument, "name is required")
	}
	if req.Slug == "" {
		return nil, status.Errorf(codes.InvalidArgument, "slug is required")
	}

	resp, err := s.clients.CreateClient(ctx, application.CreateClientRequest{
		Name:           req.Name,
		Slug:           req.Slug,
		AllowedOrigins: req.AllowedOrigins,
		WebhookURL:     req.WebhookURL,
	})
	if err != nil {
		return nil, domainToGRPCError(err)
	}

	return &CreateClientResponse{
		Client: clientToResponse(resp.Client),
		APIKey: resp.APIKey,
	}, nil
}

func (s *AdminServer) GetClient(ctx context.Context, req *GetClientRequest) (*ClientResponse, error) {
	if req.ClientID == "" {
		return nil, status.Errorf(codes.InvalidArgument, "client_id is required")
	}

	client, err := s.clients.GetClient(ctx, req.ClientID)
	if err != nil {
		return nil, domainToGRPCError(err)
	}
	if client == nil {
		return nil, status.Errorf(codes.NotFound, "client not found")
	}

	return clientToResponse(client), nil
}

func (s *AdminServer) ListClients(ctx context.Context, req *ListClientsRequest) (*ListClientsResponse, error) {
	clients, err := s.clients.ListClients(ctx)
	if err != nil {
		return nil, domainToGRPCError(err)
	}

	resp := &ListClientsResponse{
		Clients: make([]*ClientResponse, 0, len(clients)),
	}
	for _, c := range clients {
		resp.Clients = append(resp.Clients, clientToResponse(c))
	}

	return resp, nil
}

func (s *AdminServer) RotateJWTSecret(ctx context.Context, req *RotateJWTSecretRequest) (*ClientResponse, error) {
	if req.ClientID == "" {
		return nil, status.Errorf(codes.InvalidArgument, "client_id is required")
	}

	_, client, err := s.clients.RotateJWTSecret(ctx, req.ClientID)
	if err != nil {
		return nil, domainToGRPCError(err)
	}

	return clientToResponse(client), nil
}

func (s *AdminServer) RotateAPIKey(ctx context.Context, req *RotateAPIKeyRequest) (*RotateAPIKeyResponse, error) {
	if req.ClientID == "" {
		return nil, status.Errorf(codes.InvalidArgument, "client_id is required")
	}

	newKey, client, err := s.clients.RotateAPIKey(ctx, req.ClientID)
	if err != nil {
		return nil, domainToGRPCError(err)
	}

	return &RotateAPIKeyResponse{
		Client: clientToResponse(client),
		APIKey: newKey,
	}, nil
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
