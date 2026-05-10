package grpc

import (
	"context"
	"log"
	"runtime/debug"
	"strings"
	"time"

	"github.com/Ayush10/authentication-service/internal/application"
	"github.com/Ayush10/authentication-service/internal/domain"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type grpcContextKey string

const adminActorContextKey grpcContextKey = "admin_actor"

// chainUnaryInterceptors chains multiple unary interceptors into one.
func chainUnaryInterceptors(interceptors ...grpc.UnaryServerInterceptor) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Build the chain from the end.
		current := handler
		for i := len(interceptors) - 1; i >= 0; i-- {
			interceptor := interceptors[i]
			next := current
			current = func(ctx context.Context, req interface{}) (interface{}, error) {
				return interceptor(ctx, req, info, next)
			}
		}
		return current(ctx, req)
	}
}

// loggingInterceptor logs the method name, duration, and any error for each RPC.
func loggingInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	start := time.Now()
	resp, err := handler(ctx, req)
	duration := time.Since(start)

	code := codes.OK
	if err != nil {
		if st, ok := status.FromError(err); ok {
			code = st.Code()
		} else {
			code = codes.Unknown
		}
	}

	log.Printf("grpc %s | %s | %v | %v", info.FullMethod, code, duration, err)
	return resp, err
}

// recoveryInterceptor recovers from panics in gRPC handlers and returns Internal error.
func recoveryInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (resp interface{}, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("grpc panic recovered in %s: %v\n%s", info.FullMethod, r, debug.Stack())
			err = status.Error(codes.Internal, "internal server error")
		}
	}()
	return handler(ctx, req)
}

// adminAuthInterceptor authenticates admin gRPC calls with bearer admin tokens
// or the rate-limited break-glass admin API key.
func adminAuthInterceptor(adminSvc *application.AdminService, adminAPIKey string) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Only check for AdminService methods.
		if !isAdminMethod(info.FullMethod) {
			return handler(ctx, req)
		}

		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing metadata")
		}

		ip, _ := metadataFromContext(ctx)
		if keys := md.Get("x-admin-api-key"); len(keys) > 0 && strings.TrimSpace(keys[0]) != "" {
			if !application.ConstantTimeSecretEqual(strings.TrimSpace(keys[0]), adminAPIKey) {
				return nil, status.Error(codes.Unauthenticated, "invalid admin API key")
			}
			actor := &domain.AdminActor{
				Type:      domain.AdminActorTypeBreakGlass,
				ID:        "master-key",
				Email:     "break-glass-master-key",
				Roles:     []string{domain.AdminRoleOwner},
				ScopeType: domain.AdminScopeAll,
			}
			if adminSvc != nil {
				var err error
				actor, err = adminSvc.BreakGlassActor(ctx, ip)
				if err != nil {
					if err == domain.ErrRateLimit {
						return nil, status.Error(codes.ResourceExhausted, "admin authentication rate limited")
					}
					return nil, status.Error(codes.Internal, "admin authentication failed")
				}
			}
			return handler(context.WithValue(ctx, adminActorContextKey, actor), req)
		}

		authHeaders := md.Get("authorization")
		if len(authHeaders) == 0 {
			return nil, status.Error(codes.Unauthenticated, "missing admin authorization")
		}
		parts := strings.SplitN(authHeaders[0], " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") || adminSvc == nil {
			return nil, status.Error(codes.Unauthenticated, "invalid admin authorization")
		}
		actor, err := adminSvc.ValidateAccessToken(ctx, strings.TrimSpace(parts[1]))
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "invalid admin authorization")
		}
		return handler(context.WithValue(ctx, adminActorContextKey, actor), req)
	}
}

// isAdminMethod checks if the gRPC method belongs to the AdminService.
func isAdminMethod(fullMethod string) bool {
	// fullMethod format is "/package.ServiceName/MethodName"
	return len(fullMethod) > 13 && fullMethod[:14] == "/auth.v1.Admin"
}

// metadataFromContext extracts common metadata values (ip, user-agent) from gRPC metadata.
func metadataFromContext(ctx context.Context) (ip, userAgent string) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", ""
	}
	if vals := md.Get("x-forwarded-for"); len(vals) > 0 {
		ip = vals[0]
	}
	if vals := md.Get("x-real-ip"); len(vals) > 0 && ip == "" {
		ip = vals[0]
	}
	if vals := md.Get("user-agent"); len(vals) > 0 {
		userAgent = vals[0]
	}
	return ip, userAgent
}

func adminActorFromContext(ctx context.Context) *domain.AdminActor {
	actor, _ := ctx.Value(adminActorContextKey).(*domain.AdminActor)
	return actor
}

func requestIDFromContext(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	if vals := md.Get("x-request-id"); len(vals) > 0 {
		return vals[0]
	}
	return ""
}
