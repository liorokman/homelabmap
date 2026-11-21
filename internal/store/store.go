// Package store persists scans, graphs, per-MAC history and web sessions in
// a single SQLite file.
package store

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	_ "modernc.org/sqlite" // database/sql driver "sqlite"

	"github.com/liorokman/homelabmap/internal/obs"
	"github.com/liorokman/homelabmap/internal/topo"
)

// Scan states.
const (
	StatusPending = "pending"
	StatusRunning = "running"
	StatusDone    = "done"
	StatusFailed  = "failed"
)

// TriggerProbe marks a quick scan of newly heard devices. Probes never
// hold up or replace the regular full scans.
const TriggerProbe = "probe"

var ErrNotFound = errors.New("not found")

type Store struct {
	db *sql.DB
}

// Scan is a scan row without its (large) payloads.
type Scan struct {
	ID          int64      `json:"id"`
	Trigger     string     `json:"trigger"`
	Status      string     `json:"status"`
	RequestedAt time.Time  `json:"requestedAt"`
	StartedAt   *time.Time `json:"startedAt,omitempty"`
	FinishedAt  *time.Time `json:"finishedAt,omitempty"`
	Error       string     `json:"error,omitempty"`
	Nodes       int        `json:"nodes"`
	Edges       int        `json:"edges"`
	// Targets are a probe's devices.
	Targets []obs.ProbeTarget `json:"targets,omitempty"`
}

var migrations = []string{
	`CREATE TABLE scans (
		id            INTEGER PRIMARY KEY,
		trigger       TEXT    NOT NULL,
		status        TEXT    NOT NULL,
		requested_at  INTEGER NOT NULL,
		started_at    INTEGER,
		finished_at   INTEGER,
		error         TEXT    NOT NULL DEFAULT '',
		result_gz     BLOB,
		graph_json    TEXT,
		graph_version INTEGER NOT NULL DEFAULT 0,
		node_count    INTEGER NOT NULL DEFAULT 0,
		edge_count    INTEGER NOT NULL DEFAULT 0
	);
	CREATE INDEX scans_status ON scans(status, id);
	CREATE TABLE os_scans (
		mac        TEXT PRIMARY KEY,
		scanned_at INTEGER NOT NULL,
		data       TEXT    NOT NULL
	);
	CREATE TABLE macs (
		mac        TEXT PRIMARY KEY,
		first_seen INTEGER NOT NULL,
		last_seen  INTEGER NOT NULL
	);
	CREATE TABLE sessions (
		id_hash    TEXT PRIMARY KEY,
		subject    TEXT    NOT NULL,
		name       TEXT    NOT NULL DEFAULT '',
		email      TEXT    NOT NULL DEFAULT '',
		created_at INTEGER NOT NULL,
		expires_at INTEGER NOT NULL
	);
	CREATE TABLE login_flows (
		id_hash    TEXT PRIMARY KEY,
		state      TEXT    NOT NULL,
		nonce      TEXT    NOT NULL,
		verifier   TEXT    NOT NULL,
		return_to  TEXT    NOT NULL,
		expires_at INTEGER NOT NULL
	);`,
	// 2: passive listening and probes.
	`ALTER TABLE scans ADD COLUMN targets TEXT NOT NULL DEFAULT '';
	CREATE TABLE sightings (
		mac        TEXT    NOT NULL,
		ip         TEXT    NOT NULL,
		via        TEXT    NOT NULL,
		first_seen INTEGER NOT NULL,
		last_seen  INTEGER NOT NULL,
		PRIMARY KEY (mac, ip)
	);
	CREATE INDEX sightings_last ON sightings(last_seen);
	CREATE TABLE probes (
		mac          TEXT PRIMARY KEY,
		requested_at INTEGER NOT NULL
	);`,
}

// Open opens (creating if needed) and migrates the database.
func Open(ctx context.Context, path string) (*Store, error) {
	q := url.Values{}
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "busy_timeout(10000)")
	q.Add("_pragma", "synchronous(NORMAL)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_txlock", "immediate")
	db, err := sql.Open("sqlite", "file:"+path+"?"+q.Encode())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	s := &Store{db: db}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrating %s: %w", path, err)
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	var v int
	if err := s.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&v); err != nil {
		return err
	}
	for i := v; i < len(migrations); i++ {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
		// PRAGMA can't take parameters; i is an int we control.
		if _, err := tx.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version = %d`, i+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func unix(t time.Time) int64 { return t.Unix() }

func fromUnix(n sql.NullInt64) *time.Time {
	if !n.Valid {
		return nil
	}
	t := time.Unix(n.Int64, 0).UTC()
	return &t
}

const scanCols = `id, trigger, status, requested_at, started_at, finished_at, error, node_count, edge_count, targets`

func scanRow(r interface{ Scan(...any) error }, extra ...any) (*Scan, error) {
	var sc Scan
	var req int64
	var started, finished sql.NullInt64
	var targets string
	dest := append([]any{&sc.ID, &sc.Trigger, &sc.Status, &req, &started, &finished, &sc.Error, &sc.Nodes, &sc.Edges, &targets}, extra...)
	if err := r.Scan(dest...); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	sc.RequestedAt = time.Unix(req, 0).UTC()
	sc.StartedAt, sc.FinishedAt = fromUnix(started), fromUnix(finished)
	if targets != "" {
		if err := json.Unmarshal([]byte(targets), &sc.Targets); err != nil {
			return nil, fmt.Errorf("scan %d targets: %w", sc.ID, err)
		}
	}
	return &sc, nil
}

// Enqueue adds a pending full scan unless one is already pending or
// running, in which case that one is returned with created=false.
func (s *Store) Enqueue(ctx context.Context, trigger string, now time.Time) (sc *Scan, created bool, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	sc, err = scanRow(tx.QueryRowContext(ctx,
		`SELECT `+scanCols+` FROM scans WHERE status IN (?, ?) AND trigger <> ? ORDER BY id LIMIT 1`,
		StatusPending, StatusRunning, TriggerProbe))
	switch {
	case err == nil:
		return sc, false, nil
	case !errors.Is(err, ErrNotFound):
		return nil, false, err
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO scans (trigger, status, requested_at) VALUES (?, ?, ?)`,
		trigger, StatusPending, unix(now))
	if err != nil {
		return nil, false, err
	}
	id, _ := res.LastInsertId()
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	return &Scan{ID: id, Trigger: trigger, Status: StatusPending, RequestedAt: now.UTC().Truncate(time.Second)}, true, nil
}

// Claim marks the oldest pending scan as running and returns it.
func (s *Store) Claim(ctx context.Context, now time.Time) (*Scan, error) {
	return scanRow(s.db.QueryRowContext(ctx,
		`UPDATE scans SET status = ?, started_at = ?
		 WHERE id = (SELECT id FROM scans WHERE status = ? ORDER BY id LIMIT 1)
		 RETURNING `+scanCols, StatusRunning, unix(now), StatusPending))
}

// FailStale fails scans that have been running since before cutoff.
func (s *Store) FailStale(ctx context.Context, cutoff, now time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE scans SET status = ?, finished_at = ?, error = 'scanner did not report back in time'
		 WHERE status = ? AND started_at < ?`, StatusFailed, unix(now), StatusRunning, unix(cutoff))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func gz(b []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(b); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Complete stores a finished scan's raw result and graph. It only accepts
// results for a scan that is currently running. Every MAC on the map
// counts as seen.
func (s *Store) Complete(ctx context.Context, id int64, res *obs.Result, g *topo.Graph, now time.Time) error {
	var seen []string
	for _, n := range g.Nodes {
		if !n.Absent {
			seen = append(seen, n.MACs...)
		}
	}
	return s.complete(ctx, id, res, g, seen, now)
}

// CompleteProbe stores a probe merged into the latest full scan. Only the
// probed MACs count as seen: the rest of the map is older news.
func (s *Store) CompleteProbe(ctx context.Context, id int64, merged *obs.Result, g *topo.Graph, probed []string, now time.Time) error {
	return s.complete(ctx, id, merged, g, probed, now)
}

func (s *Store) complete(ctx context.Context, id int64, res *obs.Result, g *topo.Graph, seenMACs []string, now time.Time) error {
	raw, err := json.Marshal(res)
	if err != nil {
		return err
	}
	z, err := gz(raw)
	if err != nil {
		return err
	}
	gj, err := json.Marshal(g)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	r, err := tx.ExecContext(ctx,
		`UPDATE scans SET status = ?, finished_at = ?, result_gz = ?, graph_json = ?, graph_version = ?,
		 node_count = ?, edge_count = ?, error = ? WHERE id = ? AND status = ?`,
		StatusDone, unix(now), z, string(gj), g.Version, len(g.Nodes), len(g.Edges), "", id, StatusRunning)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n != 1 {
		return fmt.Errorf("scan %d is not running: %w", id, ErrNotFound)
	}
	// Remember the MACs seen, and fresh OS fingerprints.
	seen := unix(res.StartedAt)
	for _, m := range seenMACs {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO macs (mac, first_seen, last_seen) VALUES (?, ?, ?)
			 ON CONFLICT(mac) DO UPDATE SET last_seen = MAX(last_seen, excluded.last_seen)`, m, seen, seen); err != nil {
			return err
		}
	}
	for _, o := range res.OSScans {
		d, err := json.Marshal(o)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO os_scans (mac, scanned_at, data) VALUES (?, ?, ?)
			 ON CONFLICT(mac) DO UPDATE SET scanned_at = excluded.scanned_at, data = excluded.data`,
			o.MAC, unix(o.ScannedAt), string(d)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Fail marks a running scan failed.
func (s *Store) Fail(ctx context.Context, id int64, msg string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE scans SET status = ?, finished_at = ?, error = ? WHERE id = ? AND status = ?`,
		StatusFailed, unix(now), msg, id, StatusRunning)
	return err
}

// Active returns the pending or running full scan, if any.
func (s *Store) Active(ctx context.Context) (*Scan, error) {
	return scanRow(s.db.QueryRowContext(ctx,
		`SELECT `+scanCols+` FROM scans WHERE status IN (?, ?) AND trigger <> ? ORDER BY id LIMIT 1`,
		StatusPending, StatusRunning, TriggerProbe))
}

// Get returns one scan.
func (s *Store) Get(ctx context.Context, id int64) (*Scan, error) {
	return scanRow(s.db.QueryRowContext(ctx, `SELECT `+scanCols+` FROM scans WHERE id = ?`, id))
}

// LastRequested is when the most recent full scan was requested (zero if none).
func (s *Store) LastRequested(ctx context.Context) (time.Time, error) {
	var t sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT MAX(requested_at) FROM scans WHERE trigger <> ?`, TriggerProbe).Scan(&t); err != nil {
		return time.Time{}, err
	}
	if !t.Valid {
		return time.Time{}, nil
	}
	return time.Unix(t.Int64, 0).UTC(), nil
}

// Recent lists the latest scans, newest first.
func (s *Store) Recent(ctx context.Context, limit int) ([]Scan, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+scanCols+` FROM scans ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Scan
	for rows.Next() {
		sc, err := scanRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *sc)
	}
	return out, rows.Err()
}

// LatestGraph returns the newest successful scan and its graph JSON.
func (s *Store) LatestGraph(ctx context.Context) (*Scan, []byte, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+scanCols+`, graph_json FROM scans
		WHERE status = ? AND graph_json IS NOT NULL ORDER BY id DESC LIMIT 1`, StatusDone)
	var gj string
	sc, err := scanRow(row, &gj)
	if err != nil {
		return nil, nil, err
	}
	return sc, []byte(gj), nil
}

// Result loads a scan's raw observations.
func (s *Store) Result(ctx context.Context, id int64) (*obs.Result, error) {
	var z []byte
	if err := s.db.QueryRowContext(ctx, `SELECT result_gz FROM scans WHERE id = ? AND result_gz IS NOT NULL`, id).Scan(&z); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	r, err := gzip.NewReader(bytes.NewReader(z))
	if err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var res obs.Result
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// StaleGraphs lists done scans whose graph was built by an older topo.Version.
func (s *Store) StaleGraphs(ctx context.Context, version int, limit int) ([]int64, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM scans WHERE status = ? AND result_gz IS NOT NULL
		AND graph_version <> ? ORDER BY id DESC LIMIT ?`, StatusDone, version, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// Graph returns one scan's stored graph.
func (s *Store) Graph(ctx context.Context, id int64) (*topo.Graph, error) {
	var gj sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT graph_json FROM scans WHERE id = ?`, id).Scan(&gj)
	if errors.Is(err, sql.ErrNoRows) || err == nil && !gj.Valid {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var g topo.Graph
	if err := json.Unmarshal([]byte(gj.String), &g); err != nil {
		return nil, err
	}
	return &g, nil
}

// UpdateGraph replaces a scan's graph (after an inference upgrade).
func (s *Store) UpdateGraph(ctx context.Context, id int64, g *topo.Graph) error {
	gj, err := json.Marshal(g)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE scans SET graph_json = ?, graph_version = ?, node_count = ?, edge_count = ? WHERE id = ?`,
		string(gj), g.Version, len(g.Nodes), len(g.Edges), id)
	return err
}

// History is the per-MAC memory the inference uses.
func (s *Store) History(ctx context.Context) (topo.History, error) {
	h := topo.History{OSScans: map[string]obs.OSScan{}, FirstSeen: map[string]time.Time{},
		LastSeen: map[string]time.Time{}, IPv6: map[string][]string{}}
	rows, err := s.db.QueryContext(ctx, `SELECT data FROM os_scans`)
	if err != nil {
		return h, err
	}
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			rows.Close()
			return h, err
		}
		var o obs.OSScan
		if json.Unmarshal([]byte(d), &o) == nil && o.MAC != "" {
			h.OSScans[o.MAC] = o
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return h, err
	}

	rows, err = s.db.QueryContext(ctx, `SELECT mac, first_seen, last_seen FROM macs`)
	if err != nil {
		return h, err
	}
	for rows.Next() {
		var m string
		var first, last int64
		if err := rows.Scan(&m, &first, &last); err != nil {
			rows.Close()
			return h, err
		}
		h.FirstSeen[m] = time.Unix(first, 0).UTC()
		h.LastSeen[m] = time.Unix(last, 0).UTC()
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return h, err
	}

	rows, err = s.db.QueryContext(ctx, `SELECT mac, ip, last_seen FROM sightings ORDER BY mac, last_seen DESC`)
	if err != nil {
		return h, err
	}
	for rows.Next() {
		var m, ip string
		var last int64
		if err := rows.Scan(&m, &ip, &last); err != nil {
			rows.Close()
			return h, err
		}
		if t := time.Unix(last, 0).UTC(); t.After(h.LastSeen[m]) {
			h.LastSeen[m] = t
		}
		if strings.Contains(ip, ":") {
			h.IPv6[m] = append(h.IPv6[m], ip)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return h, err
	}

	var since sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT MIN(started_at) FROM scans WHERE status = ?`, StatusDone).Scan(&since); err != nil {
		return h, err
	}
	if since.Valid {
		h.Since = time.Unix(since.Int64, 0).UTC()
	}
	return h, nil
}

// KnownMACs lists every MAC ever placed on the map.
func (s *Store) KnownMACs(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT mac FROM macs ORDER BY mac`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var m string
		if err := rows.Scan(&m); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// OSScanTimes maps MAC -> last fingerprint attempt.
func (s *Store) OSScanTimes(ctx context.Context) (map[string]time.Time, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT mac, scanned_at FROM os_scans`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var m string
		var t int64
		if err := rows.Scan(&m, &t); err != nil {
			return nil, err
		}
		out[m] = time.Unix(t, 0).UTC()
	}
	return out, rows.Err()
}

// Prune drops scan payloads older than cutoff (keeping the newest good
// graph) and expired sessions and login flows.
func (s *Store) Prune(ctx context.Context, cutoff, now time.Time) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM scans WHERE requested_at < ? AND status IN (?, ?)
		AND id <> COALESCE((SELECT MAX(id) FROM scans WHERE status = ?), 0)`,
		unix(cutoff), StatusDone, StatusFailed, StatusDone); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM sightings WHERE last_seen < ?`, unix(cutoff)); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM probes WHERE requested_at < ?`, unix(cutoff)); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ?`, unix(now)); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM login_flows WHERE expires_at < ?`, unix(now))
	return err
}
