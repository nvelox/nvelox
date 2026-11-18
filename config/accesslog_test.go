package config

import "testing"

// logging.access turns the access log of every listener on or off, a
// listener's own access_log wins over it, and with neither set the log is
// on. The values read as YAML's on and off.
func TestLoad_AccessLogSwitch(t *testing.T) {
	const rest = `listeners:
  - name: plain
    bind: "127.0.0.1:18080"
    protocol: http
    backend: be
  - name: quiet
    bind: "127.0.0.1:18081"
    protocol: http
    backend: be
    access_log: off
  - name: loud
    bind: "127.0.0.1:18082"
    protocol: tcp
    backend: be
    access_log: on
backends:
  - name: be
    servers: ["127.0.0.1:9000"]
`
	for _, c := range []struct {
		logging string
		want    map[string]bool
	}{
		{"", map[string]bool{"plain": true, "quiet": false, "loud": true}},
		{"logging:\n  access: on\n", map[string]bool{"plain": true, "quiet": false, "loud": true}},
		{"logging:\n  access: off\n", map[string]bool{"plain": false, "quiet": false, "loud": true}},
	} {
		cfg, err := loadYAML(t, "version: \"2\"\n"+c.logging+rest)
		if err != nil {
			t.Fatalf("%q: %v", c.logging, err)
		}
		for i := range cfg.Listeners {
			l := &cfg.Listeners[i]
			if got := l.AccessLogOn(); got != c.want[l.Name] {
				t.Errorf("%q: listener %s: access log %v, want %v", c.logging, l.Name, got, c.want[l.Name])
			}
		}
	}
}
