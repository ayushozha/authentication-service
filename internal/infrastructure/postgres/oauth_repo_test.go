package postgres

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/Ayush10/authentication-service/internal/domain"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

func TestProviderSubjectCreationRollsBackFailedLinkAndCanRetry(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	admin, err := OpenDB(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	schema := "auth_binding_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(`CREATE SCHEMA ` + pq.QuoteIdentifier(schema)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(`DROP SCHEMA ` + pq.QuoteIdentifier(schema) + ` CASCADE`) })
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	query := u.Query()
	query.Set("search_path", schema)
	u.RawQuery = query.Encode()
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for _, name := range []string{"001_create_clients.sql", "002_create_users.sql", "004_create_oauth_accounts.sql"} {
		migration, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(string(migration)); err != nil {
			t.Fatal(err)
		}
	}
	clientID := uuid.NewString()
	if _, err := db.Exec(`INSERT INTO clients (id, name, slug, jwt_secret, api_key_hash) VALUES ($1, 'Fixture', 'fixture', 'fixture', 'fixture')`, clientID); err != nil {
		t.Fatal(err)
	}
	repo := NewOAuthRepo(db)
	ctx := context.Background()
	create := func(subject, email string) (*domain.User, error) {
		return repo.CreateProviderSubjectAccount(ctx, clientID, "google", subject, email, "Fixture", "", "provider-access", "", []byte(`{}`))
	}
	first, err := create("existing-subject", "first@example.test")
	if err != nil {
		t.Fatal(err)
	}
	// The link's unique provider constraint fails after the user CTE executes.
	// The same statement must roll back that user, leaving a later retry usable.
	if _, err := create("existing-subject", "retry@example.test"); err == nil {
		t.Fatal("duplicate provider link unexpectedly succeeded")
	}
	var stranded int
	if err := db.QueryRow(`SELECT count(*) FROM users WHERE email = 'retry@example.test'`).Scan(&stranded); err != nil || stranded != 0 {
		t.Fatalf("failed link stranded %d users: %v", stranded, err)
	}
	retried, err := create("new-subject", "retry@example.test")
	if err != nil || retried == nil {
		t.Fatalf("strict retry after failed link: %#v, %v", retried, err)
	}
	if _, err := create("third-subject", "first@example.test"); !errors.Is(err, domain.ErrDuplicateEmail) {
		t.Fatalf("email conflict must fail explicitly, got %v", err)
	}
	if _, err := repo.FindByProvider(ctx, clientID, "google", "third-subject"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("email conflict created a provider link: %v", err)
	}
	existing, err := repo.FindByProvider(ctx, clientID, "google", "existing-subject")
	if err != nil || existing.UserID != first.ID {
		t.Fatalf("failed link reassigned original owner: %#v, %v", existing, err)
	}
}
