package sniff

// Deduper suppresses repeats of the same MAC/IP pair within a window, so a
// chatty device costs one sighting per window. Times are in seconds.
type Deduper struct {
	window int64
	last   map[string]int64
}

func NewDeduper(windowSeconds int64) *Deduper {
	return &Deduper{window: windowSeconds, last: map[string]int64{}}
}

// Fresh reports whether s should be passed on at time now, and records it.
func (d *Deduper) Fresh(s Sighting, now int64) bool {
	k := s.MAC + "|" + s.IP.String()
	if t, ok := d.last[k]; ok && now-t < d.window {
		return false
	}
	d.last[k] = now
	if len(d.last) > 50000 { // bound memory on a hostile segment
		for k, t := range d.last {
			if now-t >= d.window {
				delete(d.last, k)
			}
		}
	}
	return true
}
