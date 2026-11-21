package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"time"

	"github.com/liorokman/homelabmap/internal/obs"
)

// SightingRow is one MAC/IP pair heard passively.
type SightingRow struct {
	MAC       string    `json:"mac"`
	IP        string    `json:"ip"`
	Via       string    `json:"via"`
	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
}

// RecordSightings stores what the passive listener heard and returns the
// MACs never seen before (not on any map, never probed) that have an IPv4
// address to probe, with every IPv4 address known for them.
func (s *Store) RecordSightings(ctx context.Context, ss []obs.Sighting, now time.Time) ([]obs.ProbeTarget, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }() // no-op after Commit
	var macs []string
	for _, x := range ss {
		at := x.At
		if at.IsZero() || at.After(now) {
			at = now
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO sightings (mac, ip, via, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)
			 ON CONFLICT(mac, ip) DO UPDATE SET last_seen = MAX(last_seen, excluded.last_seen), via = excluded.via`,
			x.MAC, x.IP, x.Via, unix(at), unix(at)); err != nil {
			return nil, err
		}
		if !slices.Contains(macs, x.MAC) {
			macs = append(macs, x.MAC)
		}
	}
	var out []obs.ProbeTarget
	for _, m := range macs {
		var known int
		if err := tx.QueryRowContext(ctx,
			`SELECT (SELECT COUNT(*) FROM macs WHERE mac = ?) + (SELECT COUNT(*) FROM probes WHERE mac = ?)`, m, m).Scan(&known); err != nil {
			return nil, err
		}
		if known > 0 {
			continue
		}
		ips, err := ipv4For(ctx, tx, m)
		if err != nil {
			return nil, err
		}
		if len(ips) > 0 {
			out = append(out, obs.ProbeTarget{MAC: m, IPs: ips})
		}
	}
	return out, tx.Commit()
}

func ipv4For(ctx context.Context, tx *sql.Tx, mac string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT ip FROM sightings WHERE mac = ? ORDER BY last_seen DESC`, mac)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		if a, err := netip.ParseAddr(ip); err == nil && a.Is4() {
			out = append(out, ip)
		}
	}
	return out, rows.Err()
}

// EnqueueProbe queues a probe for new devices, at most maxPerHour devices
// an hour (randomised Wi-Fi MACs could otherwise keep nmap busy). Devices
// are remembered as probed either way, so each is probed once.
//
// If a full scan is already pending it will cover them, so no probe is
// queued; if a probe is pending they join it. It returns the probe (nil if
// none was needed) and the MACs accepted.
func (s *Store) EnqueueProbe(ctx context.Context, targets []obs.ProbeTarget, maxPerHour int, now time.Time) (*Scan, []string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = tx.Rollback() }() // no-op after Commit

	var recent int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM probes WHERE requested_at > ?`,
		unix(now.Add(-time.Hour))).Scan(&recent); err != nil {
		return nil, nil, err
	}
	if budget := maxPerHour - recent; budget < len(targets) {
		targets = targets[:max(budget, 0)]
	}
	if len(targets) == 0 {
		return nil, nil, nil
	}
	var accepted []string
	for _, t := range targets {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO probes (mac, requested_at) VALUES (?, ?)`, t.MAC, unix(now)); err != nil {
			return nil, nil, err
		}
		accepted = append(accepted, t.MAC)
	}

	var fullPending int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM scans WHERE status = ? AND trigger <> ?`,
		StatusPending, TriggerProbe).Scan(&fullPending); err != nil {
		return nil, nil, err
	}
	if fullPending > 0 {
		return nil, accepted, tx.Commit()
	}

	pending, err := scanRow(tx.QueryRowContext(ctx,
		`SELECT `+scanCols+` FROM scans WHERE status = ? AND trigger = ? ORDER BY id LIMIT 1`, StatusPending, TriggerProbe))
	switch {
	case err == nil:
		pending.Targets = mergeTargets(pending.Targets, targets)
		b, err := json.Marshal(pending.Targets)
		if err != nil {
			return nil, nil, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE scans SET targets = ? WHERE id = ?`, string(b), pending.ID); err != nil {
			return nil, nil, err
		}
		return pending, accepted, tx.Commit()
	case !errors.Is(err, ErrNotFound):
		return nil, nil, err
	}
	b, err := json.Marshal(targets)
	if err != nil {
		return nil, nil, err
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO scans (trigger, status, requested_at, targets) VALUES (?, ?, ?, ?)`,
		TriggerProbe, StatusPending, unix(now), string(b))
	if err != nil {
		return nil, nil, err
	}
	id, _ := res.LastInsertId()
	if err := tx.Commit(); err != nil {
		return nil, nil, err
	}
	return &Scan{ID: id, Trigger: TriggerProbe, Status: StatusPending, RequestedAt: now.UTC().Truncate(time.Second), Targets: targets}, accepted, nil
}

func mergeTargets(have, add []obs.ProbeTarget) []obs.ProbeTarget {
	for _, t := range add {
		i := slices.IndexFunc(have, func(h obs.ProbeTarget) bool { return h.MAC == t.MAC })
		if i < 0 {
			have = append(have, t)
			continue
		}
		for _, ip := range t.IPs {
			if !slices.Contains(have[i].IPs, ip) {
				have[i].IPs = append(have[i].IPs, ip)
			}
		}
	}
	return have
}

// Sightings lists what the passive listener heard, most recent first.
func (s *Store) Sightings(ctx context.Context, limit int) ([]SightingRow, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT mac, ip, via, first_seen, last_seen FROM sightings ORDER BY last_seen DESC, mac, ip LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SightingRow{}
	for rows.Next() {
		var r SightingRow
		var first, last int64
		if err := rows.Scan(&r.MAC, &r.IP, &r.Via, &first, &last); err != nil {
			return nil, err
		}
		r.FirstSeen, r.LastSeen = time.Unix(first, 0).UTC(), time.Unix(last, 0).UTC()
		out = append(out, r)
	}
	return out, rows.Err()
}

// LatestResult returns the raw observations behind the current map.
func (s *Store) LatestResult(ctx context.Context) (*obs.Result, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `SELECT id FROM scans WHERE status = ? AND result_gz IS NOT NULL
		ORDER BY id DESC LIMIT 1`, StatusDone).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return s.Result(ctx, id)
}
