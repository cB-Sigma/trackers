package teltonika

import (
	"github.com/cB-Sigma/trackers/track"
)

// Named commands as Teltonika SMS/GPRS commands (wiki.teltonika-gps.com,
// FMB SMS/GPRS command list). The interval parameter differs by model and
// network state, so it has no default.
var (
	namedDefaults = map[string]string{
		track.ActionEngineStop:   "setdigout 1",
		track.ActionEngineResume: "setdigout 0",
		track.ActionLocate:       "getrecord",
		track.ActionReboot:       "cpureset",
	}
	// Interval bounds the interval command, in seconds.
	Interval = track.IntervalRange{Min: 1, Max: 2592000}
	// NamedActions are the named commands Teltonika has a default text
	// for; the interval works only once namedCommands gives its text.
	NamedActions = []string{track.ActionEngineStop, track.ActionEngineResume, track.ActionLocate, track.ActionReboot}
)

// commandText is the text of a command: a named command's, or {"text"}.
func commandText(named track.NamedTemplates, imei string, content any) (string, error) {
	n, ok, err := track.ReadNamed(content)
	if err != nil {
		return "", err
	}
	if ok {
		return track.NamedText("teltonika", n, named, namedDefaults, Interval, imei, "")
	}
	return track.CommandText(content)
}
