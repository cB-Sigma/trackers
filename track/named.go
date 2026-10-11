package track

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Named commands: the same few operations under one name on every tracker
// protocol, so a fleet application need not know each protocol's syntax.
//
//	{"action": "engineStop"}                 # immobiliser on: cut fuel or ignition through the device's relay
//	{"action": "engineStop", "force": true}  # also while the vehicle is reported moving (a server's own guard)
//	{"action": "engineResume"}               # immobiliser off
//	{"action": "locate"}                     # ask for one position report now
//	{"action": "reboot"}                     # restart the device
//	{"action": "interval", "seconds": 30}    # reporting interval while moving
//
// Each codec maps them to its protocol's own command (Named); a named
// command the protocol lacks fails with the reason (Unsupported, which
// wraps ErrUnsupported). Each protocol package lists the actions it has
// (NamedActions) and the bounds of its interval command. A profile may
// replace the text of any of them for firmware that differs
// (namedCommands, NamedTemplates.Expand), with the placeholders {seconds},
// {password} (the device's commandPassword) and {imei}.
//
// The answer is the protocol's: where the device answers (GT06, Teltonika,
// AIS-140, …) the answer completes the command and a failure word fails it;
// where it does not (TK103) the command answers nothing.

// The named actions.
const (
	ActionEngineStop   = "engineStop"
	ActionEngineResume = "engineResume"
	ActionLocate       = "locate"
	ActionReboot       = "reboot"
	ActionInterval     = "interval"
)

// Actions lists the named actions in catalogue order.
var Actions = []string{ActionEngineStop, ActionEngineResume, ActionLocate, ActionReboot, ActionInterval}

// Named is a named command read from command content.
type Named struct {
	Action string
	// Seconds is the interval of ActionInterval.
	Seconds int
	// Force sends an engine stop while the vehicle is reported moving.
	Force bool
}

// ReadNamed reads a named command: ok is false when content has no
// "action" member (another command form, such as {"text": …}).
func ReadNamed(content any) (Named, bool, error) {
	m, isMap := content.(map[string]any)
	if !isMap {
		return Named{}, false, nil
	}
	a, has := m["action"]
	if !has {
		return Named{}, false, nil
	}
	action, _ := a.(string)
	known := false
	for _, x := range Actions {
		known = known || x == action
	}
	if !known {
		return Named{}, true, fmt.Errorf("action %q is not one of %s", a, strings.Join(Actions, ", "))
	}
	n := Named{Action: action}
	for k, v := range m {
		switch k {
		case "action":
		case "force":
			b, ok := v.(bool)
			if !ok || action != ActionEngineStop {
				return Named{}, true, errors.New(`force is true or false, and only for engineStop`)
			}
			n.Force = b
		case "seconds":
			if action != ActionInterval {
				return Named{}, true, fmt.Errorf("seconds is only for action %s", ActionInterval)
			}
			s, err := wholeNumber(v)
			if err != nil {
				return Named{}, true, fmt.Errorf("seconds: %w", err)
			}
			n.Seconds = s
		default:
			return Named{}, true, fmt.Errorf("%s takes no member %q", action, k)
		}
	}
	if action == ActionInterval && n.Seconds <= 0 {
		return Named{}, true, errors.New(`interval needs "seconds", a whole number above 0`)
	}
	return n, true, nil
}

func wholeNumber(v any) (int, error) {
	switch x := v.(type) {
	case float64:
		if x != float64(int(x)) {
			return 0, errors.New("not a whole number")
		}
		return int(x), nil
	case int:
		return x, nil
	case json.Number:
		i, err := strconv.Atoi(string(x))
		return i, err
	case string:
		return strconv.Atoi(x)
	}
	return 0, errors.New("not a number")
}

// ErrUnsupported marks a named command the protocol has no command for.
var ErrUnsupported = errors.New("not supported by this protocol")

// Unsupported is the error of a named command a protocol lacks; why says
// what to do instead.
func Unsupported(kind, action, why string) error {
	msg := fmt.Sprintf("%s has no %s command", kind, action)
	if why != "" {
		msg += ": " + why
	}
	return fmt.Errorf("%s (%w)", msg, ErrUnsupported)
}

// IntervalRange bounds the interval command of a protocol, in seconds;
// Step, when set, is the unit the protocol counts in (from 0).
type IntervalRange struct{ Min, Max, Step int }

// NamedTemplates is a profile's namedCommands: action → the device command
// text, with {seconds}, {password} and {imei}. A template replaces the
// codec's default for that action; "" turns the action off (the device
// has no such command).
type NamedTemplates map[string]string

// Check refuses unknown actions and placeholders; {password} only where
// the protocol's commands carry the device's commandPassword.
func (t NamedTemplates) Check(password bool) error {
	keys := make([]string, 0, len(t))
	for k := range t {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !contains(Actions, k) {
			return fmt.Errorf("namedCommands: %q is not one of %s", k, strings.Join(Actions, ", "))
		}
		rest := t[k]
		for _, p := range []string{"{seconds}", "{password}", "{imei}"} {
			rest = strings.ReplaceAll(rest, p, "")
		}
		if i := strings.IndexByte(rest, '{'); i >= 0 {
			return fmt.Errorf("namedCommands.%s: unknown placeholder in %q (use {seconds}, {password} or {imei})", k, t[k])
		}
		if !password && strings.Contains(t[k], "{password}") {
			return fmt.Errorf("namedCommands.%s: {password} is not available: this protocol's devices have no commandPassword; write the password into the text", k)
		}
		if k != ActionInterval && strings.Contains(t[k], "{seconds}") {
			return fmt.Errorf("namedCommands.%s: {seconds} is only for %s", k, ActionInterval)
		}
	}
	return nil
}

// Template returns the profile's text for action, falling back to def; ok
// is false when neither has one.
func (t NamedTemplates) Template(action, def string) (string, bool) {
	if v, set := t[action]; set {
		return v, v != ""
	}
	return def, def != ""
}

// Expand fills a template.
func Expand(tmpl string, n Named, imei, password string) string {
	r := strings.NewReplacer("{seconds}", strconv.Itoa(n.Seconds), "{password}", password, "{imei}", imei)
	return r.Replace(tmpl)
}

// NamedText resolves a named command to its text for protocols whose
// commands are text: the profile's template for the action, else def's.
// The interval is checked against iv first.
func NamedText(kind string, n Named, t NamedTemplates, def map[string]string, iv IntervalRange, imei, password string) (string, error) {
	if n.Action == ActionInterval {
		if err := iv.check(n.Seconds); err != nil {
			return "", err
		}
	}
	tmpl, ok := t.Template(n.Action, def[n.Action])
	if !ok {
		return "", Unsupported(kind, n.Action, "set profile.namedCommands."+n.Action+" to the device's command text, or send it as text")
	}
	if strings.Contains(tmpl, "{password}") && password == "" {
		return "", fmt.Errorf("%s %s needs the device's commandPassword", kind, n.Action)
	}
	return Expand(tmpl, n, imei, password), nil
}

func (iv IntervalRange) check(s int) error {
	if iv.Min > 0 && s < iv.Min || iv.Max > 0 && s > iv.Max {
		return fmt.Errorf("seconds %d is outside %d to %d", s, iv.Min, iv.Max)
	}
	if iv.Step > 1 && s%iv.Step != 0 {
		return fmt.Errorf("seconds %d: the interval is counted in steps of %d s; use %d or %d", s, iv.Step, s/iv.Step*iv.Step, (s/iv.Step+1)*iv.Step)
	}
	return nil
}

// Check bounds an interval.
func (iv IntervalRange) Check(s int) error { return iv.check(s) }

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
