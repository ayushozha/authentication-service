package application

import (
	"context"
	"errors"

	"github.com/Ayush10/authentication-service/internal/domain"
)

func enforcedSSOConnectionForEmail(ctx context.Context, repo EnterpriseSSORepository, clientID, email string) (*domain.EnterpriseSSOConnection, bool, error) {
	if repo == nil {
		return nil, false, nil
	}
	emailDomain := domain.EmailDomain(email)
	if emailDomain == "" {
		return nil, false, nil
	}
	connection, err := repo.GetActiveConnectionByDomain(ctx, clientID, emailDomain)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, false, nil
		}
		return nil, false, err
	}
	if connection == nil || connection.Status != domain.SSOConnectionStatusActive || !connection.EnforceForDomains {
		return connection, false, nil
	}
	return connection, true, nil
}
