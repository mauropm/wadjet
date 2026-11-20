// Package auth implements authentication: bcrypt password hashing and
// opaque session tokens stored in PostgreSQL.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/mauropm/wadjet/internal/database"
	"github.com/mauropm/wadjet/internal/models"
)

// Sentinel errors.
var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrEmailTaken         = errors.New("email already registered")
	ErrUnauthenticated    = errors.New("not authenticated")
	ErrWeakPassword       = errors.New("password must be at least 10 characters")
)

const sessionLifetime = 72 * time.Hour

// Service provides authentication operations.
type Service struct {
	db     *database.DB
	secret []byte
}

// NewService creates an auth service. secret adds entropy to token hashing.
func NewService(db *database.DB, secret string) *Service {
	return &Service{db: db, secret: []byte(secret)}
}

// HasUsers reports whether any account exists (bootstrap gate).
func (s *Service) HasUsers(ctx context.Context) bool {
	var count int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&count); err != nil {
		return true // fail closed: on error assume users exist
	}
	return count > 0
}

// EnsureAdmin creates the bootstrap admin account when no users exist.
func (s *Service) EnsureAdmin(ctx context.Context, email, password string) error {
	var count int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	if len(password) < 10 {
		return fmt.Errorf("bootstrap admin password must be at least 10 characters")
	}
	_, err := s.CreateUser(ctx, email, "Administrator", password, "admin")
	return err
}

// CreateUser registers a new user.
func (s *Service) CreateUser(ctx context.Context, email, name, password, role string) (*models.User, error) {
	if len(password) < 10 {
		return nil, ErrWeakPassword
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return nil, err
	}
	email = strings.ToLower(strings.TrimSpace(email))
	u := &models.User{}
	err = s.db.QueryRow(ctx,
		`INSERT INTO users (email, name, password_hash, role)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id, email, name, role, created_at`,
		email, name, string(hash), role).
		Scan(&u.ID, &u.Email, &u.Name, &u.Role, &u.CreatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return nil, ErrEmailTaken
		}
		return nil, err
	}
	return u, nil
}

// Login validates credentials and issues a session token. The token is
// EnsureUserByEmail creates the account when no row with that email exists
// (idempotent). Used by development no-login mode to guarantee the
// impersonated admin exists even in databases seeded with other users.
func (s *Service) EnsureUserByEmail(ctx context.Context, email, name, password, role string) error {
	var count int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM users WHERE email = $1`,
		strings.ToLower(strings.TrimSpace(email))).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	_, err := s.CreateUser(ctx, email, name, password, role)
	return err
}

// UserByEmail loads an account by email (case-insensitive). Used by the
// development no-login mode to resolve the bootstrap admin principal.
func (s *Service) UserByEmail(ctx context.Context, email string) (*models.User, error) {
	var u models.User
	err := s.db.QueryRow(ctx,
		`SELECT id, email, name, role FROM users WHERE email = $1`,
		strings.ToLower(strings.TrimSpace(email))).
		Scan(&u.ID, &u.Email, &u.Name, &u.Role)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// returned once; only its SHA-256 hash is stored.
func (s *Service) Login(ctx context.Context, email, password string) (*models.User, string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	var (
		u    models.User
		hash string
	)
	err := s.db.QueryRow(ctx,
		`SELECT id, email, name, role, password_hash FROM users WHERE email = $1`, email).
		Scan(&u.ID, &u.Email, &u.Name, &u.Role, &hash)
	if err != nil {
		// Constant-ish time: still run a bcrypt compare.
		_ = bcrypt.CompareHashAndPassword([]byte("$2a$10$invalidinvalidinvalidinvalidinvalidinvali123456789012"), []byte(password))
		return nil, "", ErrInvalidCredentials
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return nil, "", ErrInvalidCredentials
	}

	token, err := randomToken()
	if err != nil {
		return nil, "", err
	}
	_, err = s.db.Exec(ctx,
		`INSERT INTO sessions (user_id, token_hash, expires_at) VALUES ($1, $2, $3)`,
		u.ID, s.hashToken(token), time.Now().Add(sessionLifetime))
	if err != nil {
		return nil, "", err
	}
	return &u, token, nil
}

// Authenticate resolves a session token to a user.
func (s *Service) Authenticate(ctx context.Context, token string) (*models.User, error) {
	if token == "" {
		return nil, ErrUnauthenticated
	}
	var u models.User
	err := s.db.QueryRow(ctx,
		`SELECT u.id, u.email, u.name, u.role, u.created_at
		 FROM sessions s JOIN users u ON u.id = s.user_id
		 WHERE s.token_hash = $1 AND s.expires_at > now()`,
		s.hashToken(token)).
		Scan(&u.ID, &u.Email, &u.Name, &u.Role, &u.CreatedAt)
	if err != nil {
		return nil, ErrUnauthenticated
	}
	return &u, nil
}

// Logout revokes a session token.
func (s *Service) Logout(ctx context.Context, token string) error {
	_, err := s.db.Exec(ctx, `DELETE FROM sessions WHERE token_hash = $1`, s.hashToken(token))
	return err
}

// UserByID fetches a user.
func (s *Service) UserByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	var u models.User
	err := s.db.QueryRow(ctx,
		`SELECT id, email, name, role, created_at FROM users WHERE id = $1`, id).
		Scan(&u.ID, &u.Email, &u.Name, &u.Role, &u.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *Service) hashToken(token string) string {
	h := sha256.New()
	h.Write(s.secret)
	h.Write([]byte(token))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func randomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// CompareTokens is a constant-time string comparison helper.
func CompareTokens(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
