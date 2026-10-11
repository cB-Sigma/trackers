package tk103

import (
	"github.com/cB-Sigma/trackers/track"
)

// Named commands as Coban (GPS103) GPRS command letters.
var (
	namedDefaults = map[string]string{
		track.ActionEngineStop:   "J",
		track.ActionEngineResume: "K",
		track.ActionLocate:       "B",
		track.ActionInterval:     "C,{seconds}s",
	}
	// Interval bounds the interval command, in seconds.
	Interval = track.IntervalRange{Min: 10, Max: 86400}
	// NamedActions are the named commands TK103 has: all but reboot.
	NamedActions = []string{track.ActionEngineStop, track.ActionEngineResume, track.ActionLocate, track.ActionInterval}
)

// commandText is the text of a command: a named command's, or {"text"}.
func commandText(named track.NamedTemplates, imei string, content any) (string, error) {
	n, ok, err := track.ReadNamed(content)
	if err != nil {
		return "", err
	}
	if ok {
		return track.NamedText("tk103", n, named, namedDefaults, Interval, imei, "")
	}
	return track.CommandText(content)
}
