package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// writeConfig writes body as dir/name and returns its path.
func writeStrictFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const strictBase = `version: '2'
listeners:
  - name: web
    bind: "127.0.0.1:18080"
    protocol: http
    backend: be
backends:
  - name: be
    servers:
      - "127.0.0.1:19090"
`

// A misspelled key used to load and change nothing. It is refused, with the
// file, the line, where it stands and the key that was meant.
func TestLoad_UnknownKeyRefused(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name, body string
		want       []string
	}{
		{"a listener key one letter short", strings.Replace(strictBase, "    backend: be\n", "    backend: be\n    ip_denylst:\n      - 10.0.0.0/8\n", 1),
			[]string{"nvelox.yaml:7:5:", `unknown setting "ip_denylst"`, "in listeners[0]", `did you mean "ip_denylist"?`}},
		{"a top-level key", strings.Replace(strictBase, "backends:", "backnds:", 1),
			[]string{"nvelox.yaml:7:1:", `unknown setting "backnds"`, "at the top level", `did you mean "backends"?`}},
		{"two neighbours swapped", strings.Replace(strictBase, "    protocol: http\n", "    protocol: http\n    max_body_szie: 1MB\n", 1),
			[]string{`unknown setting "max_body_szie"`, `did you mean "max_body_size"?`}},
		{"a key written one level off", strictBase + "server:\n  ip_denylist:\n    - 10.0.0.0/8\n",
			[]string{`unknown setting "ip_denylist"`, "in server", `"ip_denylist" is a setting of listeners[]`}},
		{"a key of a nested block", strings.Replace(strictBase, "    backend: be\n", "    backend: be\n    timeouts:\n      idel: 30s\n", 1),
			[]string{`unknown setting "idel"`, "in listeners[0].timeouts", `did you mean "idle"?`}},
		{"a key of a backend", strings.Replace(strictBase, "    servers:", "    ballance: leastconn\n    servers:", 1),
			[]string{`unknown setting "ballance"`, "in backends[0]", `did you mean "balance"?`}},
		{"a key nothing is near", strictBase + "frobnicate: true\n",
			[]string{`unknown setting "frobnicate" at the top level`}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Load(writeStrictFile(t, dir, "nvelox.yaml", c.body))
			wantErr(t, err, c.want...)
		})
	}
	// The unchanged config loads.
	if _, err := Load(writeStrictFile(t, dir, "nvelox.yaml", strictBase)); err != nil {
		t.Fatalf("the base config: %v", err)
	}
}

// Every unknown key of a file is reported, each once, and a file in another
// format does not answer with a line per key.
func TestLoad_UnknownKeys_AllReported(t *testing.T) {
	dir := t.TempDir()
	body := strings.Replace(strictBase, "    backend: be\n", "    backend: be\n    one_typo: 1\n    two_typo: 2\n", 1)
	_, err := Load(writeStrictFile(t, dir, "nvelox.yaml", body))
	wantErr(t, err, `"one_typo"`, `"two_typo"`)
	if n := strings.Count(err.Error(), "unknown setting"); n != 2 {
		t.Fatalf("two unknown keys: %d reported in %q", n, err)
	}

	var many strings.Builder
	many.WriteString(strictBase)
	for i := 0; i < maxKeyErrors+7; i++ {
		many.WriteString("stray_" + string(rune('a'+i)) + ": 1\n")
	}
	_, err = Load(writeStrictFile(t, dir, "nvelox.yaml", many.String()))
	wantErr(t, err, "and 7 more unknown settings")
	if n := strings.Count(err.Error(), "unknown setting \""); n != maxKeyErrors {
		t.Fatalf("%d unknown keys listed, want the first %d", n, maxKeyErrors)
	}
}

// The names under a map are the user's own (a header, a status code): they
// are not keys of the config.
func TestLoad_MapKeysAreFree(t *testing.T) {
	dir := t.TempDir()
	body := strings.Replace(strictBase, "    backend: be\n",
		"    backend: be\n    headers:\n      request_add:\n        X-Any-Header-At-All: \"1\"\n      response_set:\n        Cache-Control: no-store\n", 1)
	if _, err := Load(writeStrictFile(t, dir, "nvelox.yaml", body)); err != nil {
		t.Fatalf("header names are free: %v", err)
	}
	// What stands under a map entry is checked again.
	body = strings.Replace(strictBase, "    backend: be\n",
		"    backend: be\n    headers:\n      request_addd:\n        X-A: \"1\"\n", 1)
	_, err := Load(writeStrictFile(t, dir, "nvelox.yaml", body))
	wantErr(t, err, `unknown setting "request_addd"`, "in listeners[0].headers", `did you mean "request_add"?`)
}

// A mapping merged into another one (`<<: *anchor`) brings its keys along:
// the known ones load, and an unknown one is one finding on its own line.
func TestLoad_MergedMappings(t *testing.T) {
	dir := t.TempDir()
	good := `version: '2'
listeners:
  - &web
    name: web
    bind: "127.0.0.1:18080"
    protocol: http
    backend: be
  - <<: *web
    name: web2
    bind: "127.0.0.1:18081"
backends:
  - name: be
    servers:
      - "127.0.0.1:19090"
`
	cfg, err := Load(writeStrictFile(t, dir, "nvelox.yaml", good))
	if err != nil {
		t.Fatalf("a merged listener: %v", err)
	}
	if len(cfg.Listeners) != 2 || cfg.Listeners[1].Backend != "be" || cfg.Listeners[1].Name != "web2" {
		t.Fatalf("the merge was not applied: %+v", cfg.Listeners)
	}
	bad := strings.Replace(good, "    backend: be\n  - <<", "    backend: be\n    protocl: http\n  - <<", 1)
	_, err = Load(writeStrictFile(t, dir, "nvelox.yaml", bad))
	wantErr(t, err, "nvelox.yaml:8:5:", `unknown setting "protocl"`, `did you mean "protocol"?`)
	if n := strings.Count(err.Error(), "unknown setting"); n != 1 {
		t.Fatalf("one key on one line, merged into two listeners: reported %d times in %q", n, err)
	}

	// A key that reaches a listener only through a merge: the anchored
	// mapping stands where its keys are free names (a set of headers), and
	// merged into a listener they are settings nothing reads. Both forms
	// of a merge, one mapping and a list of them.
	for form, merge := range map[string]string{"one mapping": "*extra", "a list of mappings": "[*extra]"} {
		viaMerge := `version: '2'
listeners:
  - name: web
    bind: "127.0.0.1:18080"
    protocol: http
    backend: be
    headers:
      request_add: &extra
        X-Only-A-Header: "1"
  - <<: ` + merge + `
    name: web2
    bind: "127.0.0.1:18081"
    protocol: http
    backend: be
backends:
  - name: be
    servers:
      - "127.0.0.1:19090"
`
		_, err = Load(writeStrictFile(t, dir, "nvelox.yaml", viaMerge))
		if err == nil {
			t.Fatalf("%s: a key merged into a listener that no setting reads must be refused", form)
		}
		wantErr(t, err, "nvelox.yaml:9:9:", `unknown setting "X-Only-A-Header"`, "in listeners[1]")
	}
}

// What stands under a free name of a map is checked against the map's
// element type. No setting of the config is a map of blocks today, so this
// holds the rule for the day one is.
func TestCheckKeys_UnderAMapEntry(t *testing.T) {
	type site struct {
		Name string `yaml:"name"`
	}
	type doc struct {
		Sites map[string]site `yaml:"sites"`
	}
	good := "sites:\n  any-name-at-all:\n    name: a\n"
	if err := checkKeys([]byte(good), "x.yaml", reflect.TypeOf(doc{})); err != nil {
		t.Fatalf("a map of blocks with known keys: %v", err)
	}
	bad := "sites:\n  any-name-at-all:\n    nmae: a\n"
	wantErr(t, checkKeys([]byte(bad), "x.yaml", reflect.TypeOf(doc{})), "x.yaml:3:5:", `unknown setting "nmae"`, "in sites.any-name-at-all", `did you mean "name"?`)
}

// An included file is held to the same rule, and it may hold listeners and
// backends only: Load reads nothing else from it.
func TestLoad_IncludedFileKeys(t *testing.T) {
	dir := t.TempDir()
	main := "version: '2'\ninclude: \"conf.d/*.yaml\"\n"
	if err := os.Mkdir(filepath.Join(dir, "conf.d"), 0o700); err != nil {
		t.Fatal(err)
	}
	mainPath := writeStrictFile(t, dir, "nvelox.yaml", main)
	frag := `listeners:
  - name: web
    bind: "127.0.0.1:18080"
    protocol: http
    backend: be
backends:
  - name: be
    servers:
      - "127.0.0.1:19090"
`
	sub := filepath.Join("conf.d", "site.yaml")
	writeStrictFile(t, dir, sub, frag)
	if _, err := Load(mainPath); err != nil {
		t.Fatalf("a fragment of listeners and backends: %v", err)
	}
	writeStrictFile(t, dir, sub, "version: '2'\n"+frag)
	if _, err := Load(mainPath); err != nil {
		t.Fatalf("a fragment that names the same version: %v", err)
	}

	writeStrictFile(t, dir, sub, strings.Replace(frag, "    backend: be\n", "    backend: be\n    ip_allowlst: []\n", 1))
	_, err := Load(mainPath)
	wantErr(t, err, "site.yaml:6:5:", `unknown setting "ip_allowlst"`, `did you mean "ip_allowlist"?`)

	writeStrictFile(t, dir, sub, frag+"logging:\n  level: debug\n")
	_, err = Load(mainPath)
	wantErr(t, err, "site.yaml:10:1:", `"logging" is read from the main config file only`)

	writeStrictFile(t, dir, sub, "version: '1'\n"+frag)
	_, err = Load(mainPath)
	wantErr(t, err, "site.yaml", `version "1" differs from the main config file's "2"`)
}

// No config this repository ships holds a key that nothing reads.
func TestShippedConfigs_NoUnknownKeys(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "examples", "*.yaml"))
	if err != nil || len(files) < 30 {
		t.Fatalf("the examples: %d found, %v", len(files), err)
	}
	files = append(files, filepath.Join("..", "nvelox.example.yaml"), filepath.Join("..", "nvelox.yaml"))
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if err := checkKeys(data, f, reflect.TypeOf(Config{})); err != nil {
			t.Errorf("%v", err)
		}
	}
}

func TestEditDistance(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"", "", 0}, {"abc", "abc", 0}, {"", "abc", 3}, {"abc", "", 3},
		{"ip_denylst", "ip_denylist", 1}, // one missing
		{"backnds", "backends", 1},
		{"max_body_szie", "max_body_size", 1}, // two neighbours swapped
		{"idel", "idle", 1},
		{"ballance", "balance", 1}, // one too many
		{"cert", "key", 3},         // two substitutions and one deletion: nothing near
	} {
		if got := editDistance(c.a, c.b); got != c.want {
			t.Errorf("editDistance(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

// The keys of a struct are named the way the decoder names them.
func TestFieldsOf(t *testing.T) {
	type inner struct {
		Deep string `yaml:"deep"`
	}
	type sample struct {
		Tagged   string `yaml:"tagged,omitempty"`
		Untagged int
		Skipped  string `yaml:"-"`
		hidden   string //nolint:unused
		Inner    inner  `yaml:",inline"`
	}
	got := fieldsOf(reflect.TypeOf(sample{}))
	for _, k := range []string{"tagged", "untagged", "deep"} {
		if _, ok := got[k]; !ok {
			t.Errorf("key %q is missing from %v", k, got)
		}
	}
	for _, k := range []string{"Skipped", "skipped", "-", "hidden", "inner", "Inner"} {
		if _, ok := got[k]; ok {
			t.Errorf("key %q must not be one", k)
		}
	}
}
