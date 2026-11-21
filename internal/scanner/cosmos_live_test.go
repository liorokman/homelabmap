package scanner

import (
	"context"
	"encoding/json"
	"os"
	"testing"
)

// TestLiveCosmos reads the real Cosmos API. Opt-in:
// HOMELABMAP_LIVE_COSMOS_OUT=/tmp/x.json HOMELABMAP_COSMOS_URL=... HOMELABMAP_COSMOS_TOKEN=... go test ./internal/scanner -run LiveCosmos
func TestLiveCosmos(t *testing.T) {
	out := os.Getenv("HOMELABMAP_LIVE_COSMOS_OUT")
	if out == "" {
		t.Skip("set HOMELABMAP_LIVE_COSMOS_OUT (and HOMELABMAP_COSMOS_URL/TOKEN) to read the real Cosmos API")
	}
	cfg := Config{CosmosURL: os.Getenv("HOMELABMAP_COSMOS_URL"), CosmosToken: os.Getenv("HOMELABMAP_COSMOS_TOKEN")}
	c, err := cosmosCollect(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.MarshalIndent(c, "", " ")
	if err := os.WriteFile(out, b, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Logf("%d containers, %d routes, host %v", len(c.Containers), len(c.Routes), c.HostIPs)
}
