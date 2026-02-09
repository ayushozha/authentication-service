package grpc

import (
	"errors"

	"github.com/Ayush10/authentication-service/internal/domain"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// domainToGRPCError maps domain errors to appropriate gRPC status codes.
func domainToGRPCError(err error) error {
	if err == nil {
		return nil
	}

	switch {
	case errors.Is(err, domain.ErrNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, domain.ErrDuplicateEmail):
		return status.Error(codes.AlreadyExists, err.Error())
	case errors.Is(err, domain.ErrInvalidToken):
		return status.Error(codes.Unauthenticated, err.Error())
	case errors.Is(err, domain.ErrInvalidPassword):
		return status.Error(codes.Unauthenticated, err.Error())
	case errors.Is(err, domain.ErrAccountSuspended):
		return status.Error(codes.PermissionDenied, err.Error())
	case errors.Is(err, domain.ErrAccountLocked):
		return status.Error(codes.PermissionDenied, err.Error())
	case errors.Is(err, domain.ErrRateLimit):
		return status.Error(codes.ResourceExhausted, err.Error())
	case errors.Is(err, domain.ErrInvalidClient):
		return status.Error(codes.Unauthenticated, err.Error())
	case errors.Is(err, domain.ErrClientSuspended):
		return status.Error(codes.PermissionDenied, err.Error())
	case errors.Is(err, domain.ErrEmailNotConfigured):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, domain.ErrRedisRequired):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, domain.ErrEmailAlreadyVerified):
		return status.Error(codes.AlreadyExists, err.Error())
	case errors.Is(err, domain.ErrWeakPassword):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, domain.ErrTOTPRequired):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, domain.ErrTOTPInvalid):
		return status.Error(codes.InvalidArgument, err.Error())
	default:
		return status.Errorf(codes.Internal, "internal error")
	}
}
