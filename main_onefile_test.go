package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestMainIsOneFile: main.go must build on its own. The README, the
// Dockerfile and deploy tooling run `go build -o nvelox main.go`, which
// compiles that one file, so another non-test file in package main breaks
// their builds. Put such code (e.g. per-OS values) in a package main.go
// imports.
func TestMainIsOneFile(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if f != "main.go" && !strings.HasSuffix(f, "_test.go") {
			t.Errorf("%s is in package main: `go build main.go` does not compile it", f)
		}
	}
}
