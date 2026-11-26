package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// ErrConflict means the settings changed since they were read.
var ErrConflict = errors.New("the settings were changed elsewhere")

// SettingsRow is the stored Settings page: an opaque JSON document (its
// secrets are encrypted by the web before they get here) and its version.
type SettingsRow struct {
	Doc     string
	Version int64
	// ScannerImported is set once the scanner's environment was imported.
	ScannerImported bool
	UpdatedAt       time.Time
}

// GetSettings returns the stored settings, or ErrNotFound before the first
// save.
func (s *Store) GetSettings(ctx context.Context) (*SettingsRow, error) {
	var r SettingsRow
	var updated int64
	err := s.db.QueryRowContext(ctx, `SELECT doc, version, scanner_imported, updated_at FROM settings WHERE id = 1`).
		Scan(&r.Doc, &r.Version, &r.ScannerImported, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	r.UpdatedAt = time.Unix(updated, 0).UTC()
	return &r, nil
}

// PutSettings saves the document if the stored version is still
// expectVersion (0: nothing stored yet), and returns the new version. A
// concurrent change returns ErrConflict.
func (s *Store) PutSettings(ctx context.Context, doc string, expectVersion int64, scannerImported bool, now time.Time) (int64, error) {
	var res sql.Result
	var err error
	if expectVersion == 0 {
		res, err = s.db.ExecContext(ctx, `INSERT INTO settings (id, doc, version, scanner_imported, updated_at)
			VALUES (1, ?, 1, ?, ?) ON CONFLICT (id) DO NOTHING`, doc, scannerImported, unix(now))
	} else {
		res, err = s.db.ExecContext(ctx, `UPDATE settings SET doc = ?, version = version + 1, scanner_imported = ?, updated_at = ?
			WHERE id = 1 AND version = ?`, doc, scannerImported, unix(now), expectVersion)
	}
	if err != nil {
		return 0, err
	}
	if n, err := res.RowsAffected(); err != nil {
		return 0, err
	} else if n == 0 {
		return 0, ErrConflict
	}
	return expectVersion + 1, nil
}
