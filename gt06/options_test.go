package gt06_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/cB-Sigma/trackers/gt06"
)

// A 0x80 command ends with the language bytes by default; with
// commandLanguage false it ends with the text, for firmware that takes
// commands only that way.
//
// Covers: SIG-CMD-010
func TestCommandLanguageOption(t *testing.T) {
	for profile, lang := range map[string]bool{``: true, `{"commandLanguage": true}`: true, `{"commandLanguage": false}`: false} {
		nc, err := gt06.NewCodec(json.RawMessage(profile))
		if err != nil {
			t.Fatal(err)
		}
		f, answers, err := nc().Command(imei, map[string]any{"text": "WHERE#"}, 7)
		if err != nil || !answers {
			t.Fatalf("%s: %v", profile, err)
		}
		// 78 78 len 80 | len flag(4) text [00 02] | serial(2) crc(2) 0D 0A
		body := f[4 : len(f)-6]
		if got := bytes.HasSuffix(body, []byte{0x00, 0x02}); got != lang {
			t.Errorf("%q: language bytes %v, want %v (% X)", profile, got, lang, f)
		}
		if body[0] != byte(4+len("WHERE#")) {
			t.Errorf("%q: length byte %d", profile, body[0])
		}
	}
}

// The words that fail a command's answer are a profile setting; the
// default is error, fail and invalid.
//
// Covers: SIG-CMD-013
func TestFailureWordsOption(t *testing.T) {
	if ms := decodeAll(t, "", vAnswer21); len(ms) != 1 || ms[0] == nil || !ms[0].Failed {
		t.Fatalf("default: %+v", ms)
	}
	if ms := decodeAll(t, `{"failureWords": ["refused"]}`, vAnswer21); len(ms) != 1 || ms[0] == nil || ms[0].Failed {
		t.Fatalf("failureWords [refused] failed %q", *ms[0].Response)
	}
	if _, err := gt06.NewCodec(json.RawMessage(`{"failureWords": [" "]}`)); err == nil {
		t.Fatal("a blank failure word was accepted")
	}
}
