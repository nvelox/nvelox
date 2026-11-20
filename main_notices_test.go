package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestThirdPartyNoticesFollowGoMod: THIRD_PARTY_NOTICES.md reproduces the
// licences of the versions compiled in, so each module it lists carries, in
// its table row and in its section heading, the version go.mod requires, and
// the Go toolchain is the one go.mod names.
func TestThirdPartyNoticesFollowGoMod(t *testing.T) {
	mod, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	required := map[string]string{}
	toolchain := ""
	for _, line := range strings.Split(string(mod), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "toolchain" {
			toolchain = f[1]
			continue
		}
		if len(f) >= 3 && f[0] == "require" {
			f = f[1:]
		}
		if len(f) >= 2 && strings.Contains(f[0], ".") && strings.HasPrefix(f[1], "v") {
			required[f[0]] = f[1]
		}
	}
	if toolchain == "" || len(required) == 0 {
		t.Fatalf("go.mod read as toolchain %q and %d requirements", toolchain, len(required))
	}

	b, err := os.ReadFile("THIRD_PARTY_NOTICES.md")
	if err != nil {
		t.Fatal(err)
	}
	notices := string(b)
	listed := 0
	for _, re := range []*regexp.Regexp{
		regexp.MustCompile(`(?m)^\| ([a-z0-9.-]+\.[a-z]+/[^ |\n]+) \| ([^ |\n]+) \|`), // table rows
		regexp.MustCompile(`(?m)^## ([a-z0-9.-]+\.[a-z]+/[^ \n]+) ([^ \n]+)$`),        // section headings
	} {
		for _, m := range re.FindAllStringSubmatch(notices, -1) {
			listed++
			if v, ok := required[m[1]]; !ok {
				t.Errorf("THIRD_PARTY_NOTICES.md lists %s %s, which go.mod does not require", m[1], m[2])
			} else if v != m[2] {
				t.Errorf("THIRD_PARTY_NOTICES.md lists %s %s; go.mod requires %s", m[1], m[2], v)
			}
		}
	}
	if listed == 0 {
		t.Fatal("no module found in THIRD_PARTY_NOTICES.md")
	}
	goName := "The Go programming language"
	if !strings.Contains(notices, "| "+goName+" (runtime and standard library) | "+toolchain+" |") ||
		!strings.Contains(notices, "\n## "+goName+" "+toolchain+"\n") {
		t.Errorf("THIRD_PARTY_NOTICES.md does not name the toolchain go.mod names, %s, in its table and its heading", toolchain)
	}
}
