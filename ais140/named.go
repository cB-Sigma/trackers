package ais140

import (
	"strconv"

	"github.com/cB-Sigma/trackers/track"
)

// Named commands (track.Named) on AIS-140. Table 4D has a restart
// (ID 018) and the ignition-on reporting interval (ID 014), so reboot is
// SET 018:1 and interval is SET 014:<seconds>, framed with the device's
// password like any Table 4D command and completed by its OTA response.
// Table 4D has no immobiliser and no position request: engineStop,
// engineResume and locate fail with the reason unless the profile's
// namedCommands gives the manufacturer's own line (relay commands differ
// by maker; that line is sent as it is and answered as free text).

// Interval bounds SET 014 (seconds).
var Interval = track.IntervalRange{Min: 1, Max: 3600}

// NamedActions are the named commands Table 4D has.
var NamedActions = []string{track.ActionReboot, track.ActionInterval}

// resolveNamed turns a named command into the Table 4D command or the
// profile's line; other content is returned as it is.
func (c *Config) resolveNamed(content any, imei, password string) (any, error) {
	n, ok, err := track.ReadNamed(content)
	if !ok || err != nil {
		return content, err
	}
	if _, set := c.named[n.Action]; set {
		line, err := track.NamedText("ais140", n, c.named, nil, Interval, imei, password)
		if err != nil {
			return nil, err
		}
		return map[string]any{"text": line}, nil
	}
	switch n.Action {
	case track.ActionReboot:
		return map[string]any{"op": "SET", "param": "018", "value": "1"}, nil
	case track.ActionInterval:
		if err := Interval.Check(n.Seconds); err != nil {
			return nil, err
		}
		return map[string]any{"op": "SET", "param": "014", "value": strconv.Itoa(n.Seconds)}, nil
	}
	return nil, track.Unsupported("AIS-140 Table 4D", n.Action,
		"set profile.namedCommands."+n.Action+" to the manufacturer's command line, or send it as text")
}
