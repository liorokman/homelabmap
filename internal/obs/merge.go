package obs

import "maps"

// MergeProbe overlays a probe result on a full scan, so newly heard
// devices appear without waiting for the next full scan. base is not
// modified. Probe data wins where both describe the same IP or MAC.
func MergeProbe(base, probe *Result) *Result {
	if base == nil {
		out := *probe
		return &out
	}
	out := *base
	out.JobID = probe.JobID
	out.StartedAt, out.FinishedAt = probe.StartedAt, probe.FinishedAt
	out.Probe = true

	ips, macs := map[string]bool{}, map[string]bool{}
	for _, h := range probe.Sweep {
		ips[h.IP] = true
		if h.MAC != "" {
			macs[h.MAC] = true
		}
	}
	out.Sweep = make([]SweepHost, 0, len(base.Sweep)+len(probe.Sweep))
	for _, h := range base.Sweep {
		if !ips[h.IP] && (h.MAC == "" || !macs[h.MAC]) {
			out.Sweep = append(out.Sweep, h)
		}
	}
	out.Sweep = append(out.Sweep, probe.Sweep...)

	scanned := map[string]bool{}
	for _, o := range probe.OSScans {
		scanned[o.MAC] = true
	}
	out.OSScans = nil
	for _, o := range base.OSScans {
		if !scanned[o.MAC] {
			out.OSScans = append(out.OSScans, o)
		}
	}
	out.OSScans = append(out.OSScans, probe.OSScans...)

	out.DNS = maps.Clone(base.DNS)
	if out.DNS == nil {
		out.DNS = map[string]string{}
	}
	maps.Copy(out.DNS, probe.DNS)

	if probe.UniFi != nil {
		out.UniFi = probe.UniFi
	}
	if probe.PVE != nil {
		out.PVE = probe.PVE
	}
	out.Errors = append(append([]string(nil), base.Errors...), probe.Errors...)
	return &out
}
