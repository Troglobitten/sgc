// Package auth owns the admin account, the one-time setup link and login
// sessions.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"time"
)

var (
	// ErrAlreadySetUp means an admin account exists, so setup is closed for good.
	ErrAlreadySetUp = errors.New("SGC is already set up")
	// ErrBadSetupToken means the setup link is wrong, used or expired.
	ErrBadSetupToken = errors.New("the setup link is not valid or has expired")
	// ErrInvalidCredentials deliberately does not say which part was wrong.
	ErrInvalidCredentials = errors.New("wrong username or password")
	// ErrWrongPassword is for a signed-in admin asked for the password again.
	ErrWrongPassword   = errors.New("that is not your password")
	ErrInvalidUsername = errors.New("a username is 1 to 32 characters: lowercase letters, digits, dot, dash or underscore, starting with a letter")
	ErrWeakPassword    = fmt.Errorf("a password must be at least %d characters", MinPasswordLength)
	ErrPasswordTooLong = fmt.Errorf("a password can be at most %d characters", maxPasswordLength)
)

// TooManyAttemptsError is returned while an address is locked out.
type TooManyAttemptsError struct{ RetryAfter time.Duration }

func (e *TooManyAttemptsError) Error() string {
	return fmt.Sprintf("too many wrong attempts; try again in %d seconds", int(e.RetryAfter.Seconds())+1)
}

const (
	MinPasswordLength = 12
	// Hashing cost grows with input length; without a cap, a huge "password"
	// would be a cheap way to keep the gateway busy.
	maxPasswordLength = 256

	// A session ends after sessionIdle without use, and after sessionMax in any case.
	sessionIdle = 12 * time.Hour
	sessionMax  = 7 * 24 * time.Hour

	tokenBytes = 32
)

var usernamePattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,31}$`)

// Service is safe for use by several goroutines.
type Service struct {
	db      *sql.DB
	now     func() time.Time
	params  hashParams
	limiter *limiter

	// A hash to verify against when the username is unknown, so that a wrong
	// username takes as long to reject as a wrong password.
	decoyHash string
}

func NewService(db *sql.DB) (*Service, error) {
	return newService(db, time.Now, defaultParams)
}

func newService(db *sql.DB, now func() time.Time, params hashParams) (*Service, error) {
	decoy, err := hashPassword("decoy-password-never-matches", params)
	if err != nil {
		return nil, err
	}
	return &Service{db: db, now: now, params: params, limiter: newLimiter(), decoyHash: decoy}, nil
}

// SetupRequired reports whether SGC still has no admin account.
func (s *Service) SetupRequired(ctx context.Context) (bool, error) {
	var count int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM admin").Scan(&count); err != nil {
		return false, fmt.Errorf("check for admin account: %w", err)
	}
	return count == 0, nil
}

// NewSetupToken creates the secret part of the one-time setup link, replacing
// any earlier one. Only its hash is stored.
func (s *Service) NewSetupToken(ctx context.Context, validFor time.Duration) (string, error) {
	required, err := s.SetupRequired(ctx)
	if err != nil {
		return "", err
	}
	if !required {
		return "", ErrAlreadySetUp
	}

	token, hash, err := newToken()
	if err != nil {
		return "", err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO setup_token (id, token_hash, expires_at) VALUES (1, ?, ?)
		 ON CONFLICT (id) DO UPDATE SET token_hash = excluded.token_hash, expires_at = excluded.expires_at`,
		hash, s.now().Add(validFor).Unix())
	if err != nil {
		return "", fmt.Errorf("store setup token: %w", err)
	}
	return token, nil
}

// CompleteSetup creates the admin account if token is the current setup token.
// The token is used up in the same step, so the link works exactly once.
func (s *Service) CompleteSetup(ctx context.Context, token, username, password, remoteAddr string) error {
	now := s.now()
	if wait := s.limiter.retryAfter(remoteAddr, now); wait > 0 {
		return &TooManyAttemptsError{RetryAfter: wait}
	}
	if err := validateCredentials(username, password); err != nil {
		return err
	}
	// Hash before taking the database lock: hashing is slow on purpose.
	passwordHash, err := hashPassword(password, s.params)
	if err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin setup: %w", err)
	}
	defer tx.Rollback()

	var admins int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM admin").Scan(&admins); err != nil {
		return fmt.Errorf("check for admin account: %w", err)
	}
	if admins > 0 {
		return ErrAlreadySetUp
	}

	var storedHash []byte
	var expiresAt int64
	err = tx.QueryRowContext(ctx, "SELECT token_hash, expires_at FROM setup_token WHERE id = 1").Scan(&storedHash, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		s.limiter.fail(remoteAddr, now)
		return ErrBadSetupToken
	}
	if err != nil {
		return fmt.Errorf("read setup token: %w", err)
	}
	given := sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare(given[:], storedHash) != 1 || now.Unix() >= expiresAt {
		s.limiter.fail(remoteAddr, now)
		return ErrBadSetupToken
	}

	if _, err := tx.ExecContext(ctx,
		"INSERT INTO admin (id, username, password_hash, created_at) VALUES (1, ?, ?, ?)",
		username, passwordHash, now.Unix()); err != nil {
		return fmt.Errorf("create admin account: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM setup_token"); err != nil {
		return fmt.Errorf("use up setup token: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("finish setup: %w", err)
	}
	s.limiter.succeed(remoteAddr)
	return nil
}

// CheckSetupToken reports whether token is the current setup token, without
// using it up. Restoring from an export on a fresh install is guarded by the
// same one-time link as creating an account, but takes two steps (preview,
// then confirm), so the first step must leave the link valid.
func (s *Service) CheckSetupToken(ctx context.Context, token, remoteAddr string) error {
	now := s.now()
	if wait := s.limiter.retryAfter(remoteAddr, now); wait > 0 {
		return &TooManyAttemptsError{RetryAfter: wait}
	}
	required, err := s.SetupRequired(ctx)
	if err != nil {
		return err
	}
	if !required {
		return ErrAlreadySetUp
	}

	var storedHash []byte
	var expiresAt int64
	err = s.db.QueryRowContext(ctx, "SELECT token_hash, expires_at FROM setup_token WHERE id = 1").Scan(&storedHash, &expiresAt)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read setup token: %w", err)
	}
	given := sha256.Sum256([]byte(token))
	if err != nil || subtle.ConstantTimeCompare(given[:], storedHash) != 1 || now.Unix() >= expiresAt {
		s.limiter.fail(remoteAddr, now)
		return ErrBadSetupToken
	}
	return nil
}

// VerifyAdminPassword checks the admin's password without starting a
// session. Used to ask for the password again before an action that hands
// out everything SGC holds, such as an export. Wrong attempts count towards
// the same lock-out as wrong sign-ins.
func (s *Service) VerifyAdminPassword(ctx context.Context, password, remoteAddr string) error {
	now := s.now()
	if wait := s.limiter.retryAfter(remoteAddr, now); wait > 0 {
		return &TooManyAttemptsError{RetryAfter: wait}
	}
	var storedHash string
	if err := s.db.QueryRowContext(ctx, "SELECT password_hash FROM admin WHERE id = 1").Scan(&storedHash); err != nil {
		return fmt.Errorf("read admin account: %w", err)
	}
	matches := false
	if len(password) <= maxPasswordLength {
		var err error
		if matches, err = verifyPassword(storedHash, password); err != nil {
			return err
		}
	}
	if !matches {
		s.limiter.fail(remoteAddr, now)
		return ErrWrongPassword
	}
	return nil
}

// AdminUsername returns the admin's username, or "" before setup.
func (s *Service) AdminUsername(ctx context.Context) (string, error) {
	var username string
	err := s.db.QueryRowContext(ctx, "SELECT username FROM admin WHERE id = 1").Scan(&username)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read admin account: %w", err)
	}
	return username, nil
}

// Session is a successful login.
type Session struct {
	Token    string // goes into the browser cookie; never stored
	Username string
	Expires  time.Time
}

// Login checks the credentials and starts a session.
func (s *Service) Login(ctx context.Context, username, password, remoteAddr, userAgent string) (*Session, error) {
	now := s.now()
	if wait := s.limiter.retryAfter(remoteAddr, now); wait > 0 {
		return nil, &TooManyAttemptsError{RetryAfter: wait}
	}

	var storedName, storedHash string
	err := s.db.QueryRowContext(ctx, "SELECT username, password_hash FROM admin WHERE id = 1").Scan(&storedName, &storedHash)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("read admin account: %w", err)
	}

	nameMatches := err == nil && subtle.ConstantTimeCompare([]byte(username), []byte(storedName)) == 1
	hashToCheck := storedHash
	if !nameMatches {
		hashToCheck = s.decoyHash
	}
	passwordMatches := false
	if len(password) <= maxPasswordLength {
		passwordMatches, err = verifyPassword(hashToCheck, password)
		if err != nil {
			return nil, err
		}
	}
	if !nameMatches || !passwordMatches {
		s.limiter.fail(remoteAddr, now)
		return nil, ErrInvalidCredentials
	}
	s.limiter.succeed(remoteAddr)

	token, hash, err := newToken()
	if err != nil {
		return nil, err
	}
	expires := now.Add(sessionIdle)
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO session (token_hash, username, created_at, last_seen_at, expires_at, remote_addr, user_agent)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		hash, storedName, now.Unix(), now.Unix(), expires.Unix(), remoteAddr, truncate(userAgent, 256)); err != nil {
		return nil, fmt.Errorf("store session: %w", err)
	}
	return &Session{Token: token, Username: storedName, Expires: expires}, nil
}

// Authenticate returns the session for token, extending it, or nil if the
// token is unknown or has expired.
func (s *Service) Authenticate(ctx context.Context, token string) (*Session, error) {
	if token == "" {
		return nil, nil
	}
	hash := sha256.Sum256([]byte(token))
	now := s.now()

	var username string
	var createdAt, lastSeenAt, expiresAt int64
	err := s.db.QueryRowContext(ctx,
		"SELECT username, created_at, last_seen_at, expires_at FROM session WHERE token_hash = ?", hash[:]).
		Scan(&username, &createdAt, &lastSeenAt, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read session: %w", err)
	}
	if now.Unix() >= expiresAt {
		return nil, nil
	}

	// Extend the session, but never past its absolute limit, and only write
	// when a minute has passed: the dashboard polls every few seconds and a
	// database write per request would wear an SD card for no benefit.
	expires := time.Unix(expiresAt, 0)
	if now.Unix()-lastSeenAt >= 60 {
		expires = now.Add(sessionIdle)
		if limit := time.Unix(createdAt, 0).Add(sessionMax); expires.After(limit) {
			expires = limit
		}
		if _, err := s.db.ExecContext(ctx,
			"UPDATE session SET last_seen_at = ?, expires_at = ? WHERE token_hash = ?",
			now.Unix(), expires.Unix(), hash[:]); err != nil {
			return nil, fmt.Errorf("extend session: %w", err)
		}
	}
	return &Session{Token: token, Username: username, Expires: expires}, nil
}

// Logout ends the session for token.
func (s *Service) Logout(ctx context.Context, token string) error {
	hash := sha256.Sum256([]byte(token))
	if _, err := s.db.ExecContext(ctx, "DELETE FROM session WHERE token_hash = ?", hash[:]); err != nil {
		return fmt.Errorf("end session: %w", err)
	}
	return nil
}

// DeleteExpiredSessions removes sessions that can no longer be used.
func (s *Service) DeleteExpiredSessions(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, "DELETE FROM session WHERE expires_at <= ?", s.now().Unix()); err != nil {
		return fmt.Errorf("delete expired sessions: %w", err)
	}
	return nil
}

func validateCredentials(username, password string) error {
	if !usernamePattern.MatchString(username) {
		return ErrInvalidUsername
	}
	if len(password) > maxPasswordLength {
		return ErrPasswordTooLong
	}
	// Counted in characters, so a passphrase in any script is judged fairly.
	if len([]rune(password)) < MinPasswordLength {
		return ErrWeakPassword
	}
	return nil
}

// newToken returns a random token and the hash under which it is stored.
func newToken() (token string, hash []byte, err error) {
	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("generate token: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	return token, sum[:], nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
