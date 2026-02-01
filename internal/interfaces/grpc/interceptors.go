package grpc

import (
	"context"
	"log"
	"runtime/debug"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

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
			err = status.Errorf(codes.Internal, "internal server error")
		}
	}()
	return handler(ctx, req)
}

// adminAPIKeyInterceptor verifies the admin API key from gRPC metadata
// for methods that require admin access.
func adminAPIKeyInterceptor(adminAPIKey string) grpc.UnaryServerInterceptor {
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
			return nil, status.Errorf(codes.Unauthenticated, "missing metadata")
		}

		keys := md.Get("x-admin-api-key")
		if len(keys) == 0 || keys[0] != adminAPIKey {
			return nil, status.Errorf(codes.Unauthenticated, "invalid admin API key")
		}

		return handler(ctx, req)
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
