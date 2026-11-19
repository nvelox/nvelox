package config

// The configuration reference (docs/reference/configuration.md) is made
// from this package's source: every setting the loader reads, under the
// key it is written as. Its description is the first paragraph of the
// comment above its field (or the comment after it on its line), written
// for the people who configure nvelox; what is for this code's readers
// goes in a later paragraph. A section without a comment of its own takes
// its type's. A setting without a description fails the test, so does one
// that names this code (a file, a package, a Go identifier), and so does a
// reference that is not what the source makes now: after a change, run
//
//	go test ./config -run TestReference -update-reference
//
// and commit the page with the change.

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var updateReference = flag.Bool("update-reference", false, "rewrite docs/reference/configuration.md from the source")

const referencePath = "../docs/reference/configuration.md"

// setting is one key of the configuration as the loader reads it.
type setting struct {
	path  string // "listeners[].tls.cert"
	owner string // the Go struct type that holds it
	field reflect.StructField
}

// settingsOf lists the settings under the struct type t at path in, in the
// order of its fields, each followed by the settings under it.
func settingsOf(t reflect.Type, in string, depth int) []setting {
	var out []setting
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name, opts, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if name == "-" {
			continue
		}
		if strings.Contains(","+opts+",", ",inline,") {
			out = append(out, settingsOf(structOf(f.Type), in, depth)...)
			continue
		}
		if name == "" {
			name = strings.ToLower(f.Name)
		}
		path := joinKeyPath(in, name)
		out = append(out, setting{path: path, owner: t.Name(), field: f})
		if st, under := innerStruct(f.Type, path); st != nil && depth < 8 {
			out = append(out, settingsOf(st, under, depth+1)...)
		}
	}
	return out
}

// structOf is t without the pointers in front of it.
func structOf(t reflect.Type) reflect.Type {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t
}

// innerStruct is the struct type a setting of type t holds settings of
// (itself, its elements or its values), and the path they are written
// under; nil for a setting that holds none.
func innerStruct(t reflect.Type, path string) (reflect.Type, string) {
	t = structOf(t)
	switch t.Kind() {
	case reflect.Struct:
		return t, path
	case reflect.Slice, reflect.Array:
		if e := structOf(t.Elem()); e.Kind() == reflect.Struct {
			return e, path + "[]"
		}
	case reflect.Map:
		if e := structOf(t.Elem()); e.Kind() == reflect.Struct {
			return e, path + ".<name>"
		}
	}
	return nil, ""
}

// settingKind says in words what a setting of type t is written as.
func settingKind(t reflect.Type) string {
	t = structOf(t)
	switch t.Kind() {
	case reflect.String:
		return "text"
	case reflect.Bool:
		return "true or false"
	case reflect.Int, reflect.Int64, reflect.Int32, reflect.Uint, reflect.Uint64, reflect.Uint32, reflect.Float64, reflect.Float32:
		return "number"
	case reflect.Struct:
		return "section"
	case reflect.Slice, reflect.Array:
		if structOf(t.Elem()).Kind() == reflect.Struct {
			return "list of sections"
		}
		return "list of " + settingKind(t.Elem())
	case reflect.Map:
		v := "sections"
		if structOf(t.Elem()).Kind() != reflect.Struct {
			v = settingKind(t.Elem())
		}
		return "map of " + settingKind(t.Key()) + " to " + v
	}
	return t.Kind().String()
}

// firstParagraph is a comment's text up to its first empty line.
func firstParagraph(text string) string {
	text = strings.TrimSpace(text)
	if i := strings.Index(text, "\n\n"); i >= 0 {
		text = text[:i]
	}
	return text
}

// fieldComments reads the comments of this package's source: of a struct
// field, the first paragraph of the comment above it, else the one after
// it on its line, by "Type.Field"; of a struct type, the first paragraph
// of its comment, by "Type".
func fieldComments(t *testing.T) map[string]string {
	t.Helper()
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, sp := range gd.Specs {
				ts := sp.(*ast.TypeSpec)
				st, ok := ts.Type.(*ast.StructType)
				if !ok {
					continue
				}
				doc := ts.Doc
				if doc == nil && len(gd.Specs) == 1 {
					doc = gd.Doc
				}
				out[ts.Name.Name] = firstParagraph(doc.Text())
				for _, fl := range st.Fields.List {
					text := firstParagraph(fl.Doc.Text())
					if text == "" {
						text = strings.TrimSpace(fl.Comment.Text())
					}
					for _, id := range fl.Names {
						out[ts.Name.Name+"."+id.Name] = text
					}
				}
			}
		}
	}
	return out
}

// leadingName is a Go name at the start of a comment, as Go comments
// begin ("Enabled turns ...", "Bind: ...", "AdminConfig is ..."), which the
// reference leaves out, with an "is" or "are" after it.
var leadingName = regexp.MustCompile(`^([A-Z][A-Za-z0-9]*)(?::\s*|\s+(?:is|are)\s+|\s+)`)

// description is a comment as the reference shows it: one line, without
// the Go name goName in front.
func description(goName, comment string) string {
	text := strings.Join(strings.Fields(comment), " ")
	if m := leadingName.FindStringSubmatch(text); m != nil && m[1] == goName {
		text = text[len(m[0]):]
	}
	if text != "" {
		text = strings.ToUpper(text[:1]) + text[1:]
	}
	return text
}

// sourceWords finds what a description says of this code rather than of
// the configuration: a Go file, a package path, a call, a Go identifier.
var sourceWords = regexp.MustCompile(`\w\.go\b|\b(core|config|proxy|lb|web|relay|ngx|cmd)/|\w\(\)|\b[a-z]+\.[A-Z]\w*|\b[A-Z][a-z0-9]+(?:[A-Z][a-z0-9]+)+\b|\b[A-Z][a-z]+[A-Z]{2,}\b`)

// properNames are words written in that form that are no Go identifier.
var properNames = map[string]bool{"WebSocket": true, "WebSockets": true, "FastCGI": true, "JavaScript": true, "GitHub": true, "MySQL": true, "PostgreSQL": true}

// reference is the page the source makes, the settings that have no
// description, and those whose description names this code (in source).
func reference(t *testing.T, source *[]string) (page []byte, missing []string) {
	t.Helper()
	comments := fieldComments(t)
	settings := settingsOf(reflect.TypeOf(Config{}), "", 0)
	var b bytes.Buffer
	b.WriteString("# Configuration reference\n\n")
	b.WriteString("Every setting nvelox reads from its configuration file, under the key it is written as. " +
		"`[]` stands for each item of a list, `<name>` for each key of a map. " +
		"The page is made from nvelox's source, so it names every setting of the version it comes with; " +
		"nvelox.example.yaml shows them in a configuration.\n")
	// One section for each place settings are written in, in the order
	// the first of its settings comes; a section's own key is listed in
	// the section above it.
	var order []string
	bySection := map[string][]setting{}
	for _, s := range settings {
		parent := ""
		if i := strings.LastIndex(s.path, "."); i >= 0 {
			parent = s.path[:i]
		}
		if _, ok := bySection[parent]; !ok {
			order = append(order, parent)
		}
		bySection[parent] = append(bySection[parent], s)
	}
	for _, parent := range order {
		heading := "The top level"
		if parent != "" {
			heading = "`" + parent + "`"
		}
		fmt.Fprintf(&b, "\n## %s\n\n", heading)
		for _, s := range bySection[parent] {
			key := s.path[strings.LastIndex(s.path, ".")+1:]
			desc := description(s.field.Name, comments[s.owner+"."+s.field.Name])
			if inner, _ := innerStruct(s.field.Type, s.path); desc == "" && inner != nil {
				desc = description(inner.Name(), comments[inner.Name()])
			}
			if desc == "" {
				missing = append(missing, s.path+" ("+s.owner+"."+s.field.Name+")")
			}
			for _, w := range sourceWords.FindAllString(desc, -1) {
				if !properNames[w] {
					*source = append(*source, fmt.Sprintf("%s (%s.%s): %q", s.path, s.owner, s.field.Name, w))
				}
			}
			fmt.Fprintf(&b, "- **`%s`** (%s): %s\n", key, settingKind(s.field.Type), desc)
		}
	}
	return b.Bytes(), missing
}

func TestReference(t *testing.T) {
	var source []string
	page, missing := reference(t, &source)
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("%d settings have no description: write a comment on their field:\n  %s", len(missing), strings.Join(missing, "\n  "))
	}
	if len(source) > 0 {
		t.Errorf("%d descriptions name this code, not the configuration (move it to a later paragraph of the comment):\n  %s", len(source), strings.Join(source, "\n  "))
	}
	if *updateReference {
		if err := os.MkdirAll(filepath.Dir(referencePath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(referencePath, page, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	have, err := os.ReadFile(referencePath)
	if err != nil || !bytes.Equal(have, page) {
		t.Fatalf("%s is not what the source makes (%v): run go test ./config -run TestReference -update-reference, and commit it", referencePath, err)
	}
}

// noExample are the settings no shipped configuration shows, and why: a
// setting that is refused at load, or a former name, has no example to
// give.
var noExample = map[string]string{
	"tracing":                                      "refused at load",
	"tracing.endpoint":                             "refused at load",
	"tracing.service":                              "refused at load",
	"listeners[].zero_copy":                        "refused at load",
	"listeners[].default_backend":                  "the former name of backend",
	"listeners[].sni_routes":                       "refused at load",
	"listeners[].grpc":                             "refused at load",
	"listeners[].throttle":                         "refused at load",
	"listeners[].throttle.read_rate":               "refused at load",
	"listeners[].throttle.write_rate":              "refused at load",
	"listeners[].tls.auto_cert":                    "refused at load",
	"listeners[].tls.ocsp_stapling":                "refused at load",
	"listeners[].buffering.request_body_buffer":    "refused at load",
	"listeners[].routes[].scripts":                 "refused at load",
	"listeners[].routes[].scripts.request_script":  "refused at load",
	"listeners[].routes[].scripts.response_script": "refused at load",
}

// Every setting is shown in a shipped configuration (nvelox.example.yaml or
// one of examples/*.yaml), as a key or in a comment, so that a setting
// comes with an example; noExample holds the ones that cannot have one.
func TestReference_Examples(t *testing.T) {
	files, err := filepath.Glob("../examples/*.yaml")
	if err != nil || len(files) == 0 {
		t.Fatalf("the examples: %v", err)
	}
	files = append(files, "../nvelox.example.yaml")
	var text strings.Builder
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		text.Write(b)
		text.WriteByte('\n')
	}
	var missing []string
	for _, s := range settingsOf(reflect.TypeOf(Config{}), "", 0) {
		key := s.path[strings.LastIndex(s.path, ".")+1:]
		shown := regexp.MustCompile(`(?m)^[\s#-]*` + regexp.QuoteMeta(key) + `:`).MatchString(text.String())
		_, exempt := noExample[s.path]
		switch {
		case !shown && !exempt:
			missing = append(missing, s.path)
		case shown && exempt:
			t.Errorf("%s is shown in a configuration now, yet listed in noExample (%s)", s.path, noExample[s.path])
		}
	}
	if len(missing) > 0 {
		t.Errorf("%d settings have no example: show each in nvelox.example.yaml (a comment will do):\n  %s", len(missing), strings.Join(missing, "\n  "))
	}
}
