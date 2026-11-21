package scanner

import (
	"testing"

	"github.com/liorokman/homelabmap/internal/obs"
)

func TestParseSSDPResponse(t *testing.T) {
	resp := "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nLOCATION: http://10.20.22.246:1234/desc.xml\r\n" +
		"SERVER: WebOS/4.1.0 UPnP/1.0\r\nST: urn:schemas-upnp-org:device:MediaRenderer:1\r\nUSN: uuid:abc::urn:x\r\n\r\n"
	h, ok := parseSSDPResponse([]byte(resp))
	if !ok || h.Get("Location") != "http://10.20.22.246:1234/desc.xml" || h.Get("St") != "urn:schemas-upnp-org:device:MediaRenderer:1" {
		t.Fatalf("parsed %v %v", h, ok)
	}
	if _, ok := parseSSDPResponse([]byte("NOTIFY * HTTP/1.1\r\nHOST: x\r\n\r\n")); ok {
		t.Error("a NOTIFY is not a search response")
	}
	if _, ok := parseSSDPResponse([]byte("garbage")); ok {
		t.Error("garbage parsed")
	}
}

func TestDescURLAllowed(t *testing.T) {
	cases := map[string]bool{
		"http://10.20.22.246:1234/desc.xml":     true,
		"https://10.20.22.246/desc.xml":         true,
		"http://10.20.22.89/desc.xml":          false, // another host
		"http://169.254.169.254/latest/meta":     false,
		"http://tv.local/desc.xml":               false, // names could resolve anywhere
		"file:///etc/passwd":                     false,
		"http://user:pw@10.20.22.246/desc.xml":  false,
		"gopher://10.20.22.246/":                false,
		"http://[::ffff:10.20.22.246]/desc.xml": true, // same address, mapped form
	}
	for loc, want := range cases {
		if got := descURLAllowed(loc, "10.20.22.246"); got != want {
			t.Errorf("%s: got %v", loc, got)
		}
	}
}

func TestParseDescription(t *testing.T) {
	doc := `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <device>
    <deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType>
    <friendlyName>[LG] webOS TV
      OLED55C1</friendlyName>
    <manufacturer>LG Electronics</manufacturer>
    <modelName>OLED55C1PVB</modelName>
    <modelNumber>55C1</modelNumber>
  </device>
</root>`
	var d obs.SSDPDevice
	if !parseDescription([]byte(doc), &d) {
		t.Fatal("not parsed")
	}
	if d.FriendlyName != "[LG] webOS TV OLED55C1" || d.Manufacturer != "LG Electronics" || d.ModelName != "OLED55C1PVB" ||
		d.DeviceType != "urn:schemas-upnp-org:device:MediaRenderer:1" {
		t.Errorf("got %+v", d)
	}
	if parseDescription([]byte("<html>nope</html>"), &obs.SSDPDevice{}) {
		t.Error("non-UPnP document accepted")
	}
}
