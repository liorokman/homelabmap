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
