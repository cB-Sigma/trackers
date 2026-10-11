// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package teltonika

import (
	"github.com/cB-Sigma/trackers/track"
)

// Named commands as Teltonika SMS/GPRS commands (wiki.teltonika-gps.com,
// FMB SMS/GPRS command list and FMB parameter lists). The interval sets the
// FMB data acquisition "Min Period" parameters (10000 home on stop, 10050
// home moving, 10100 and 10150 roaming, 10200 and 10250 unknown network)
// with one setparam; models with other IDs set namedCommands.interval.
var (
	namedDefaults = map[string]string{
		track.ActionEngineStop:   "setdigout 1",
		track.ActionEngineResume: "setdigout 0",
		track.ActionLocate:       "getrecord",
		track.ActionReboot:       "cpureset",
		track.ActionInterval:     "setparam 10000:{seconds};10050:{seconds};10100:{seconds};10150:{seconds};10200:{seconds};10250:{seconds}",
	}
	// Interval bounds the interval command, in seconds. Most FMB models
	// hold these parameters in 16 bits (up to 65535 s); FMB64x hold up to
	// 2592000 s. A device answers a value out of its range with an error.
	Interval = track.IntervalRange{Min: 1, Max: 2592000}
	// NamedActions are the named commands Teltonika has a default text for.
	NamedActions = []string{track.ActionEngineStop, track.ActionEngineResume, track.ActionLocate, track.ActionReboot, track.ActionInterval}
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
