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
		return status.Errorf(codes.NotFound, err.Error())
	case errors.Is(err, domain.ErrDuplicateEmail):
		return status.Errorf(codes.AlreadyExists, err.Error())
	case errors.Is(err, domain.ErrInvalidToken):
		return status.Errorf(codes.Unauthenticated, err.Error())
	case errors.Is(err, domain.ErrInvalidPassword):
		return status.Errorf(codes.Unauthenticated, err.Error())
	case errors.Is(err, domain.ErrAccountSuspended):
		return status.Errorf(codes.PermissionDenied, err.Error())
	case errors.Is(err, domain.ErrAccountLocked):
		return status.Errorf(codes.PermissionDenied, err.Error())
	case errors.Is(err, domain.ErrRateLimit):
		return status.Errorf(codes.ResourceExhausted, err.Error())
	case errors.Is(err, domain.ErrInvalidClient):
		return status.Errorf(codes.Unauthenticated, err.Error())
	case errors.Is(err, domain.ErrClientSuspended):
		return status.Errorf(codes.PermissionDenied, err.Error())
	case errors.Is(err, domain.ErrEmailNotConfigured):
		return status.Errorf(codes.FailedPrecondition, err.Error())
	case errors.Is(err, domain.ErrRedisRequired):
		return status.Errorf(codes.FailedPrecondition, err.Error())
	case errors.Is(err, domain.ErrEmailAlreadyVerified):
		return status.Errorf(codes.AlreadyExists, err.Error())
	case errors.Is(err, domain.ErrWeakPassword):
		return status.Errorf(codes.InvalidArgument, err.Error())
	case errors.Is(err, domain.ErrTOTPRequired):
		return status.Errorf(codes.FailedPrecondition, err.Error())
	case errors.Is(err, domain.ErrTOTPInvalid):
		return status.Errorf(codes.InvalidArgument, err.Error())
	default:
		return status.Errorf(codes.Internal, "internal error")
	}
}
