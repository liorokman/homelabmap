package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Session is a logged-in user. Only a hash of the cookie value is stored,
// so a leaked database does not leak usable sessions.
type Session struct {
	Subject   string
	Name      string
	Email     string
	ExpiresAt time.Time
}

func (s *Store) CreateSession(ctx context.Context, idHash string, sess Session, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions (id_hash, subject, name, email, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)`, idHash, sess.Subject, sess.Name, sess.Email, unix(now), unix(sess.ExpiresAt))
	return err
}

// GetSession returns a live session or ErrNotFound.
func (s *Store) GetSession(ctx context.Context, idHash string, now time.Time) (*Session, error) {
	var sess Session
	var exp int64
	err := s.db.QueryRowContext(ctx, `SELECT subject, name, email, expires_at FROM sessions
		WHERE id_hash = ? AND expires_at > ?`, idHash, unix(now)).Scan(&sess.Subject, &sess.Name, &sess.Email, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	sess.ExpiresAt = time.Unix(exp, 0).UTC()
	return &sess, nil
}

func (s *Store) DeleteSession(ctx context.Context, idHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id_hash = ?`, idHash)
	return err
}

// LoginFlow holds the OIDC state between redirect and callback.
type LoginFlow struct {
	State, Nonce, Verifier, ReturnTo string
	ExpiresAt                        time.Time
}

func (s *Store) CreateLoginFlow(ctx context.Context, idHash string, f LoginFlow) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO login_flows (id_hash, state, nonce, verifier, return_to, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)`, idHash, f.State, f.Nonce, f.Verifier, f.ReturnTo, unix(f.ExpiresAt))
	return err
}

// TakeLoginFlow returns and deletes a flow, so each can be used only once.
func (s *Store) TakeLoginFlow(ctx context.Context, idHash string, now time.Time) (*LoginFlow, error) {
	var f LoginFlow
	var exp int64
	err := s.db.QueryRowContext(ctx, `DELETE FROM login_flows WHERE id_hash = ? AND expires_at > ?
		RETURNING state, nonce, verifier, return_to, expires_at`, idHash, unix(now)).
		Scan(&f.State, &f.Nonce, &f.Verifier, &f.ReturnTo, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	f.ExpiresAt = time.Unix(exp, 0).UTC()
	return &f, nil
}

// LocalUser is the password account used when no OIDC provider is
// configured. PasswordHash is an encoded Argon2id hash, never the password.
type LocalUser struct {
	Username     string
	PasswordHash string
	CreatedAt    time.Time
}

// ErrUserExists is returned when the first account was already created.
var ErrUserExists = errors.New("a local account already exists")

// HasLocalUser reports whether the first-run account has been created.
func (s *Store) HasLocalUser(ctx context.Context) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM local_users)`).Scan(&n)
	return n == 1, err
}

// CreateFirstLocalUser stores the first account. It is atomic: if any
// account exists, nothing is written and ErrUserExists is returned, so two
// concurrent first-run requests can't both succeed.
func (s *Store) CreateFirstLocalUser(ctx context.Context, u LocalUser) error {
	res, err := s.db.ExecContext(ctx, `INSERT INTO local_users (username, password_hash, created_at)
		SELECT ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM local_users)`, u.Username, u.PasswordHash, unix(u.CreatedAt))
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrUserExists
	}
	return nil
}

// GetLocalUser looks an account up by name, ignoring case, or returns
// ErrNotFound.
func (s *Store) GetLocalUser(ctx context.Context, username string) (*LocalUser, error) {
	var u LocalUser
	var created int64
	err := s.db.QueryRowContext(ctx, `SELECT username, password_hash, created_at FROM local_users
		WHERE username = ?`, username).Scan(&u.Username, &u.PasswordHash, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	u.CreatedAt = time.Unix(created, 0).UTC()
	return &u, nil
}

// SetLocalPassword replaces an account's password hash, or returns
// ErrNotFound.
func (s *Store) SetLocalPassword(ctx context.Context, username, hash string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE local_users SET password_hash = ? WHERE username = ?`, hash, username)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteOtherSessions signs a user out everywhere except the session
// keepHash, and returns how many sessions it ended.
func (s *Store) DeleteOtherSessions(ctx context.Context, subject, keepHash string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE subject = ? AND id_hash != ?`, subject, keepHash)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// OnlyLocalUser returns the password account (there is at most one), or
// ErrNotFound.
func (s *Store) OnlyLocalUser(ctx context.Context) (*LocalUser, error) {
	var name string
	err := s.db.QueryRowContext(ctx, `SELECT username FROM local_users ORDER BY created_at LIMIT 1`).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return s.GetLocalUser(ctx, name)
}

// SetPasswordReset stores a reset code's hash, replacing any earlier code:
// only the latest one works.
func (s *Store) SetPasswordReset(ctx context.Context, codeHash string, expires time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM password_resets`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO password_resets (code_hash, expires_at) VALUES (?, ?)`,
		codeHash, unix(expires)); err != nil {
		return err
	}
	return tx.Commit()
}

// TakePasswordReset consumes a live reset code, so each works once. It
// returns ErrNotFound for unknown, used or expired codes.
func (s *Store) TakePasswordReset(ctx context.Context, codeHash string, now time.Time) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM password_resets WHERE expires_at <= ?`, unix(now)); err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM password_resets WHERE code_hash = ?`, codeHash)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrNotFound
	}
	return nil
}
