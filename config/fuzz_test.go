package config

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// FuzzLoad: whatever a configuration file holds, Load returns a
// configuration or an error, and neither panics nor hangs. The strict key
// check walks the document's own tree (aliases, merge keys, includes): it
// must hold for any tree the YAML parser accepts.
func FuzzLoad(f *testing.F) {
	for _, pattern := range []string{"../examples/*.yaml", "../nvelox.example.yaml", "../nvelox.yaml"} {
		paths, _ := filepath.Glob(pattern)
		for _, p := range paths {
			if b, err := os.ReadFile(p); err == nil {
				f.Add(b)
			}
		}
	}
	f.Add([]byte("version: \"2\"\n"))
	f.Add([]byte("version: \"2\"\nlisteners: &l [{name: a, bind: \":1\", protocol: tcp, backend: b}]\nbackends: [{name: b, servers: [\"127.0.0.1:1\"]}]\n"))
	f.Add([]byte("version: \"2\"\nbase: &b {protocol: tcp}\nlisteners: [{<<: *b, name: a, bind: \":1\", backend: b}]\n"))
	f.Add([]byte("version: \"2\"\ninclude: \"*.yaml\"\nlisteners: [{name: a, bind: \":1\", protocol: tcp, backend: b}]\nbackends: [{name: b, servers: [\"127.0.0.1:1\"]}]\n"))
	f.Add([]byte("&a [*a]"))
	f.Add([]byte("a: &x [&y [*x, *x], *y]\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		// The configuration names files; the fuzzer is kept from naming the
		// system's special ones (a device is refused anyway, ReadNamedFile).
		for _, dir := range [][]byte{[]byte("/dev"), []byte("/proc"), []byte("/sys")} {
			if bytes.Contains(data, dir) {
				t.Skip()
			}
		}
		p := filepath.Join(t.TempDir(), "nvelox.yaml")
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(p)
		if err == nil && cfg == nil {
			t.Fatal("Load returned neither a configuration nor an error")
		}
	})
}
