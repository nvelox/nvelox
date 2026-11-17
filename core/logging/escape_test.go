package logging

import "testing"

func TestEscapeQuoted(t *testing.T) {
	for in, want := range map[string]string{
		"plain":     "plain",
		`a"b`:       `a\x22b`,
		`a\b`:       `a\x5Cb`,
		`\x22`:      `\x5Cx22`,
		"":          "",
		"tab\there": "tab\there",
	} {
		if got := escapeQuoted(in); got != want {
			t.Errorf("escapeQuoted(%q) = %q, want %q", in, got, want)
		}
	}
}
