package config

// strict.go — a key that nothing reads is refused at load.
//
// The YAML decoder drops keys it has no field for, so a misspelled setting
// used to load without a word: `ip_denylst: [...]` started and filtered
// nothing. checkKeys walks the document next to the types it is decoded
// into and reports every such key, with the line it is on and, when one is
// near, the key that was meant.

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// maxKeyErrors bounds how many unknown keys one load reports: a file in
// another format would otherwise answer with one line per key it holds.
const maxKeyErrors = 20

// unknownKey is one key of a config file that no setting reads.
type unknownKey struct {
	line, col int
	key       string // the key as written
	in        string // where it stands: "listeners[0].tls", "" at the top level
	hint      string // what to do about it, when there is something to say
}

// checkKeys returns an error naming every mapping key of the YAML document
// data that the type t (a struct, or a pointer to one) has no field for.
// file names the document in the error. A document that is not valid YAML
// is left to the decoder, whose error says what is wrong with it.
func checkKeys(data []byte, file string, t reflect.Type) error {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil || len(doc.Content) == 0 {
		return nil
	}
	var found []unknownKey
	walkKeys(doc.Content[0], t, "", &found, map[*yaml.Node]bool{})
	return unknownKeysError(file, found)
}

func unknownKeysError(file string, found []unknownKey) error {
	// A mapping merged into several places (`<<: *anchor`) is walked once
	// for each: its unknown key is one finding, on one line.
	type at struct {
		line, col int
		key       string
	}
	seen := map[at]bool{}
	uniq := found[:0:0]
	for _, u := range found {
		if k := (at{u.line, u.col, u.key}); !seen[k] {
			seen[k] = true
			uniq = append(uniq, u)
		}
	}
	found = uniq
	if len(found) == 0 {
		return nil
	}
	var b strings.Builder
	for i, u := range found {
		if i == maxKeyErrors {
			fmt.Fprintf(&b, "\n%s: and %d more unknown settings", file, len(found)-maxKeyErrors)
			break
		}
		if i > 0 {
			b.WriteByte('\n')
		}
		where := "at the top level"
		if u.in != "" {
			where = "in " + u.in
		}
		fmt.Fprintf(&b, "%s:%d:%d: unknown setting %q %s", file, u.line, u.col, u.key, where)
		if u.hint != "" {
			fmt.Fprintf(&b, " (%s)", u.hint)
		}
	}
	return fmt.Errorf("%s", b.String())
}

// walkKeys checks the node n against the type t it is decoded into. seen
// holds the anchored nodes on the way down, so a document whose alias leads
// back to one of its own parents ends instead of going round.
func walkKeys(n *yaml.Node, t reflect.Type, in string, found *[]unknownKey, seen map[*yaml.Node]bool) {
	for n.Kind == yaml.AliasNode && n.Alias != nil {
		n = n.Alias
	}
	if seen[n] {
		return
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Struct:
		if n.Kind != yaml.MappingNode {
			return
		}
		seen[n] = true
		defer delete(seen, n)
		fields := fieldsOf(t)
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if k.Tag == "!!merge" {
				// `<<: *anchor` (or a list of them) brings another mapping's
				// keys into this one: they are this struct's keys too.
				for v.Kind == yaml.AliasNode && v.Alias != nil {
					v = v.Alias
				}
				if v.Kind == yaml.SequenceNode {
					for _, m := range v.Content {
						walkKeys(m, t, in, found, seen)
					}
				} else {
					walkKeys(v, t, in, found, seen)
				}
				continue
			}
			ft, ok := fields[k.Value]
			if !ok {
				*found = append(*found, unknownKey{line: k.Line, col: k.Column, key: k.Value, in: in, hint: keyHint(k.Value, fields)})
				continue
			}
			walkKeys(v, ft, joinKeyPath(in, k.Value), found, seen)
		}
	case reflect.Slice, reflect.Array:
		if n.Kind != yaml.SequenceNode {
			return
		}
		for i, c := range n.Content {
			walkKeys(c, t.Elem(), fmt.Sprintf("%s[%d]", in, i), found, seen)
		}
	case reflect.Map:
		// A map's keys are the user's own names (a header, a status code):
		// only what stands under them is checked.
		if n.Kind != yaml.MappingNode {
			return
		}
		for i := 0; i+1 < len(n.Content); i += 2 {
			walkKeys(n.Content[i+1], t.Elem(), joinKeyPath(in, n.Content[i].Value), found, seen)
		}
	}
}

func joinKeyPath(in, key string) string {
	if in == "" {
		return key
	}
	return in + "." + key
}

var fieldsCache sync.Map // reflect.Type -> map[string]reflect.Type

// fieldsOf returns the YAML keys the struct type t is decoded from, each
// with the type of its field, the way yaml.v3 names them: the tag's name,
// the lower-cased field name without one, the fields of an inlined struct
// as its own, and nothing for "-" or an unexported field.
func fieldsOf(t reflect.Type) map[string]reflect.Type {
	if m, ok := fieldsCache.Load(t); ok {
		return m.(map[string]reflect.Type)
	}
	m := map[string]reflect.Type{}
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
			ft := f.Type
			for ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct {
				for k, v := range fieldsOf(ft) {
					m[k] = v
				}
			}
			continue
		}
		if name == "" {
			name = strings.ToLower(f.Name)
		}
		m[name] = f.Type
	}
	fieldsCache.Store(t, m)
	return m
}

// keyHint says what the unknown key was most likely meant to be: a key of
// the same place that is one or two typing slips away, or else the places
// where a key of exactly this name does exist.
func keyHint(key string, fields map[string]reflect.Type) string {
	best, bestD := "", len(key)/3+1
	if bestD > 3 {
		bestD = 3
	}
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names) // the same hint on every run when two keys are equally near
	lower := strings.ToLower(key)
	for _, name := range names {
		if d := editDistance(lower, name); d < bestD {
			best, bestD = name, d
		}
	}
	if best != "" {
		return fmt.Sprintf("did you mean %q?", best)
	}
	if homes := keyHomes()[key]; len(homes) > 0 {
		return fmt.Sprintf("%q is a setting of %s", key, strings.Join(homes, " and of "))
	}
	return ""
}

var (
	keyHomesOnce sync.Once
	keyHomesMap  map[string][]string
)

// keyHomes maps every key of the config to the places it is a setting of
// ("listeners[]", "listeners[].tls", "the top level"), so a key written one
// level off can be pointed to where it belongs.
func keyHomes() map[string][]string {
	keyHomesOnce.Do(func() {
		keyHomesMap = map[string][]string{}
		var walk func(t reflect.Type, in string, depth int)
		walk = func(t reflect.Type, in string, depth int) {
			for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Array || t.Kind() == reflect.Map {
				if t.Kind() != reflect.Pointer {
					in += "[]"
				}
				t = t.Elem()
			}
			if t.Kind() != reflect.Struct || depth > 8 {
				return
			}
			here := in
			if here == "" {
				here = "the top level"
			}
			fields := fieldsOf(t)
			names := make([]string, 0, len(fields))
			for name := range fields {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				keyHomesMap[name] = append(keyHomesMap[name], here)
				walk(fields[name], joinKeyPath(in, name), depth+1)
			}
		}
		walk(reflect.TypeOf(Config{}), "", 0)
	})
	return keyHomesMap
}

// editDistance is the number of single-character insertions, deletions,
// substitutions and swaps of two neighbours that turn a into b.
func editDistance(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	prev2 := make([]int, len(rb)+1)
	prev := make([]int, len(rb)+1)
	cur := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			d := prev[j] + 1 // a deletion
			if v := cur[j-1] + 1; v < d {
				d = v // an insertion
			}
			if v := prev[j-1] + cost; v < d {
				d = v // a substitution
			}
			if i > 1 && j > 1 && ra[i-1] == rb[j-2] && ra[i-2] == rb[j-1] {
				if v := prev2[j-2] + 1; v < d {
					d = v // two neighbours swapped
				}
			}
			cur[j] = d
		}
		prev2, prev, cur = prev, cur, prev2
	}
	return prev[len(rb)]
}

// includeKeys are the top-level keys an included file may hold. Load reads
// its listeners and backends and nothing else; `version` is allowed so a
// fragment can say which format it is written in.
var includeKeys = map[string]bool{"listeners": true, "backends": true, "version": true}

// checkIncludeKeys refuses, in an included file, a top-level key that is a
// setting of the main config file: Load would not read it from here, so it
// would be a setting that changes nothing.
func checkIncludeKeys(data []byte, file string) error {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil || len(doc.Content) == 0 {
		return nil
	}
	n := doc.Content[0]
	if n.Kind != yaml.MappingNode {
		return nil
	}
	known := fieldsOf(reflect.TypeOf(Config{}))
	for i := 0; i+1 < len(n.Content); i += 2 {
		k := n.Content[i]
		if _, ok := known[k.Value]; ok && !includeKeys[k.Value] {
			return fmt.Errorf("%s:%d:%d: %q is read from the main config file only (an included file adds listeners and backends); move it there", file, k.Line, k.Column, k.Value)
		}
	}
	return nil
}
