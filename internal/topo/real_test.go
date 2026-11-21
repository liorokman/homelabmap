package topo

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/liorokman/homelabmap/internal/obs"
)

// TestRealResult prints the graph for a real scanner result. It is opt-in:
//
//	HOMELABMAP_REAL_RESULT=result.json go test ./internal/topo -run Real -v
func TestRealResult(t *testing.T) {
	path := os.Getenv("HOMELABMAP_REAL_RESULT")
	if path == "" {
		t.Skip("HOMELABMAP_REAL_RESULT not set")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var res obs.Result
	if err := json.Unmarshal(b, &res); err != nil {
		t.Fatal(err)
	}
	g := Build(1, &res, History{})
	byID := map[string]Node{}
	for _, n := range g.Nodes {
		byID[n.ID] = n
	}
	var lines []string
	for _, e := range g.Edges {
		lines = append(lines, fmt.Sprintf("%-9s %s[%s] -> %s[%s]  %v", e.Kind, byID[e.Source].Label, e.SourcePort,
			byID[e.Target].Label, e.TargetPort, e.Sources))
	}
	slices.Sort(lines)
	t.Logf("%d nodes, %d edges\n%s", len(g.Nodes), len(g.Edges), strings.Join(lines, "\n"))
	for _, n := range g.Nodes {
		t.Logf("%-16s %-10s %-12s ips=%v os=%q (%s) loc=%q", n.Label, n.Role, n.Icon, n.IPs, n.OS, n.OSSource, n.Location)
	}
	for _, w := range g.Warnings {
		t.Logf("warning: %s", w)
	}
}
