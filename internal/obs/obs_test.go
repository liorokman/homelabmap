package obs

import (
	"encoding/json"
	"testing"
)

func TestNormMAC(t *testing.T) {
	tests := []struct{ in, want string }{
		{"04:31:23:7F:F1:22", "04:31:23:7f:f1:22"},
		{"04-31-23-7f-f1-22", "04:31:23:7f:f1:22"},
		{"0431237ff122", "04:31:23:7f:f1:22"},
		{" 04:31:23:7f:f1:22 ", "04:31:23:7f:f1:22"},
		{"00:00:00:00:00:00", ""},
		{"ff:ff:ff:ff:ff:ff", ""},
		{"not a mac", ""},
		{"", ""},
		{"00:00:00:00:fe:80:00:00:00:00:00:00:02:00:5e:10:00:00:00:01", ""}, // InfiniBand
	}
	for _, tt := range tests {
		if got := NormMAC(tt.in); got != tt.want {
			t.Errorf("NormMAC(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestMACBits(t *testing.T) {
	if !IsLocallyAdministered("da:a1:19:00:00:01") {
		t.Error("randomized phone MAC not detected as locally administered")
	}
	if IsLocallyAdministered("04:31:23:7f:f1:22") {
		t.Error("vendor MAC reported as locally administered")
	}
	if !IsMulticast("01:80:c2:00:00:0e") {
		t.Error("LLDP multicast not detected")
	}
	if IsMulticast("04:31:23:7f:f1:22") {
		t.Error("unicast reported as multicast")
	}
}

func TestOneOrManyDecoding(t *testing.T) {
	var old Result
	if err := json.Unmarshal([]byte(`{"unifi":{"flavor":"legacy"},"cosmos":{"url":"https://c.example"}}`), &old); err != nil {
		t.Fatal(err)
	}
	if len(old.UniFi) != 1 || old.UniFi[0].Flavor != "legacy" || len(old.Cosmos) != 1 || old.Cosmos[0].URL != "https://c.example" {
		t.Errorf("stored single objects: %+v", old)
	}
	var cur Result
	if err := json.Unmarshal([]byte(`{"unifi":[{"flavor":"a"},{"flavor":"b"}],"cosmos":null}`), &cur); err != nil {
		t.Fatal(err)
	}
	if len(cur.UniFi) != 2 || cur.Cosmos != nil {
		t.Errorf("lists: %+v", cur)
	}
	if err := json.Unmarshal([]byte(`{"unifi":{"flavor":1}}`), &cur); err == nil {
		t.Error("bad object accepted")
	}
}
