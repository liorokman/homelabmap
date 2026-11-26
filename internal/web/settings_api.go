package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/liorokman/homelabmap/internal/obs"
	"github.com/liorokman/homelabmap/internal/store"
)

// envManaged are web environment variables whose values only seed the
// first settings; after that they are managed on the Settings page.
var envManaged = []string{
	"HOMELABMAP_SCAN_INTERVAL", "HOMELABMAP_RETENTION", "HOMELABMAP_FORGET_AFTER", "HOMELABMAP_OS_RESCAN",
	"HOMELABMAP_OS_SCAN_MAX", "HOMELABMAP_PROBE_MAX_PER_HOUR", "HOMELABMAP_SESSION_TTL",
}

// settings returns the current settings. Callers must not modify them.
func (s *Server) settings() *Settings { return s.cur.Load() }

// loadSettings reads the stored settings, or stores the first ones (from
// the environment's values) on first start.
func (s *Server) loadSettings(ctx context.Context) error {
	row, err := s.store.GetSettings(ctx)
	if errors.Is(err, store.ErrNotFound) {
		first := defaultSettings(s.cfg)
		_, err := s.saveSettings(ctx, &first, 0)
		return err
	}
	if err != nil {
		return err
	}
	cur, err := s.box.decode(row.Doc)
	if err != nil {
		return err
	}
	cur.Version, cur.scannerImported = row.Version, row.ScannerImported
	s.cur.Store(cur)
	if len(cur.lost) > 0 {
		s.log.Warn("some secrets in the settings can't be decrypted; re-enter them on the Settings page", "fields", cur.lost)
	}
	var ignored []string
	for _, k := range envManaged {
		if os.Getenv(k) != "" {
			ignored = append(ignored, k)
		}
	}
	if len(ignored) > 0 {
		s.log.Warn("these environment variables are ignored: they're managed on the Settings page now", "vars", ignored)
	}
	return nil
}

// saveSettings stores next if the stored version is still expect, and
// makes it current.
func (s *Server) saveSettings(ctx context.Context, next *Settings, expect int64) (*Settings, error) {
	doc, err := s.box.encode(next)
	if err != nil {
		return nil, err
	}
	v, err := s.store.PutSettings(ctx, doc, expect, next.scannerImported, s.now())
	if err != nil {
		return nil, err
	}
	saved := next.clone()
	saved.Version, saved.lost = v, nil
	s.cur.Store(saved)
	return saved, nil
}

// isAdmin: who may open the Settings page. The password account and the
// development user always may; with OIDC, members of
// HOMELABMAP_OIDC_ADMIN_GROUPS, or everyone when it is empty.
func (s *Server) isAdmin(sess *store.Session) bool {
	return strings.HasPrefix(sess.Subject, "local:") || sess.Admin || len(s.cfg.OIDCAdminGroups) == 0
}

func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if u := userFrom(r.Context()); u == nil || !u.Admin {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "Only administrators can open the settings."})
			return
		}
		next(w, r)
	}
}

type settingsResponse struct {
	Settings *Settings `json:"settings"`
	// Lost are secrets that couldn't be decrypted and must be entered again.
	Lost []string `json:"lost,omitempty"`
	// ScannerOnline tells the page whether new settings will be picked up.
	ScannerOnline bool `json:"scannerOnline"`
}

func (s *Server) settingsBody(cur *Settings) settingsResponse {
	return settingsResponse{Settings: cur.redacted(), Lost: cur.lost, ScannerOnline: s.scannerOnline()}
}

func (s *Server) handleGetSettings(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.settingsBody(s.settings()))
}

func (s *Server) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) || r.Header.Get("X-Homelabmap-Request") != "1" {
		http.Error(w, "cross-origin request refused", http.StatusForbidden)
		return
	}
	var next Settings
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&next); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Bad settings: " + err.Error()})
		return
	}
	s.settingsMu.Lock()
	defer s.settingsMu.Unlock()
	cur := s.settings()
	if next.Version != cur.Version {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "The settings were changed elsewhere. Reload the page to see them."})
		return
	}
	next.keepSecrets(cur)
	next.normalise()
	if errs := next.validate(); len(errs) > 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Some settings need fixing.", "errors": errs})
		return
	}
	next.scannerImported = cur.scannerImported
	saved, err := s.saveSettings(r.Context(), &next, cur.Version)
	if errors.Is(err, store.ErrConflict) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "The settings were changed elsewhere. Reload the page to see them."})
		return
	}
	if err != nil {
		s.serverError(w, "saving settings", err)
		return
	}
	s.log.Info("settings changed", "by", userFrom(r.Context()).Name, "version", saved.Version)
	writeJSON(w, http.StatusOK, s.settingsBody(saved))
}

// handleAgentSettings gives the scanner its settings (for the passive
// listener; jobs carry their own copy).
func (s *Server) handleAgentSettings(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.settings().forScanner())
}

// handleAgentLegacy imports the scanner's old environment, once.
func (s *Server) handleAgentLegacy(w http.ResponseWriter, r *http.Request) {
	var l obs.LegacySettings
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&l); err != nil {
		http.Error(w, "bad legacy settings", http.StatusBadRequest)
		return
	}
	s.settingsMu.Lock()
	defer s.settingsMu.Unlock()
	cur := s.settings()
	if cur.scannerImported {
		writeJSON(w, http.StatusOK, map[string]bool{"imported": false})
		return
	}
	next := cur.clone()
	took := next.importLegacy(l)
	next.normalise()
	next.scannerImported = true
	if _, err := s.saveSettings(r.Context(), next, cur.Version); err != nil {
		s.serverError(w, "importing the scanner's settings", err)
		return
	}
	if len(took) > 0 {
		s.log.Info("imported the scanner's environment into the settings", "took", took)
		if errs := next.validate(); len(errs) > 0 {
			s.log.Warn("imported settings need fixing on the Settings page", "problems", errs)
		}
		s.notifyAgent()
	}
	writeJSON(w, http.StatusOK, map[string]bool{"imported": len(took) > 0})
}

// EditSettings changes the stored settings without the page (the demo
// seeds its fictional ones with it). The result must be valid.
func (s *Server) EditSettings(ctx context.Context, edit func(*Settings)) error {
	s.settingsMu.Lock()
	defer s.settingsMu.Unlock()
	cur := s.settings()
	next := cur.clone()
	edit(next)
	next.normalise()
	if errs := next.validate(); len(errs) > 0 {
		return fmt.Errorf("invalid settings: %v", errs)
	}
	_, err := s.saveSettings(ctx, next, cur.Version)
	return err
}
