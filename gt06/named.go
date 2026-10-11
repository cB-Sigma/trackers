package gt06

import (
	"github.com/cB-Sigma/trackers/track"
)

// Named commands as Concox command texts (GT06 protocol v1.8 command list
// and the GT06N user manual's command table).
var (
	namedDefaults = map[string]string{
		track.ActionEngineStop:   "RELAY,1#",
		track.ActionEngineResume: "RELAY,0#",
		track.ActionLocate:       "WHERE#",
		track.ActionReboot:       "RESET#",
		track.ActionInterval:     "TIMER,{seconds}#",
	}
	// Interval bounds the interval command, in seconds.
	Interval = track.IntervalRange{Min: 10, Max: 18000}
	// NamedActions are the named commands GT06 has: all of them.
	NamedActions = track.Actions
)

// commandText is the text of a command: a named command's, or {"text"}.
func commandText(named track.NamedTemplates, imei string, content any) (string, error) {
	n, ok, err := track.ReadNamed(content)
	if err != nil {
		return "", err
	}
	if ok {
		return track.NamedText("gt06", n, named, namedDefaults, Interval, imei, "")
	}
	return track.CommandText(content)
}
