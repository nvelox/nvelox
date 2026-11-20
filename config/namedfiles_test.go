package config

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// plainReads lists every call of os.ReadFile and tls.LoadX509KeyPair in
// the module's code. Those read whatever a path names, a FIFO or a device
// included, so a file the configuration names is read with ReadNamedFile or
// LoadKeyPair instead; the calls left read files it does not name.
// TestPlainReads fails when the set changes, so that a new one is reviewed
// for that before this list is updated.
var plainReads = map[string]int{
	// The configuration file itself, which may be a pipe
	// (nvelox --check --config <(generate)).
	"config/config.go Load os.ReadFile": 1,
	// The status of each of nvelox's threads (/proc/self/task), to see that
	// every one has switched user.
	"core/privdrop/privdrop_linux.go threadsIn os.ReadFile": 1,
}

func TestPlainReads(t *testing.T) {
	root := ".."
	got := map[string]int{}
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); path != root && (strings.HasPrefix(n, ".") || n == "testdata" || n == "tools" || n == "examples") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			name := "(package level)"
			if ok {
				name = fd.Name.Name
			}
			ast.Inspect(decl, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				id, ok := sel.X.(*ast.Ident)
				if !ok {
					return true
				}
				if fn := id.Name + "." + sel.Sel.Name; fn == "os.ReadFile" || fn == "tls.LoadX509KeyPair" {
					got[rel+" "+name+" "+fn]++
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var diff []string
	for k, n := range got {
		if plainReads[k] != n {
			diff = append(diff, fmt.Sprintf("in the code: %s x%d (listed x%d)", k, n, plainReads[k]))
		}
	}
	for k := range plainReads {
		if got[k] == 0 {
			diff = append(diff, "listed, gone from the code: "+k)
		}
	}
	if len(diff) > 0 {
		sort.Strings(diff)
		t.Fatalf("the plain reads changed (a file the configuration names is read with ReadNamedFile or LoadKeyPair):\n  %s", strings.Join(diff, "\n  "))
	}
}
