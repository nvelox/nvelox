// Package httppath puts request paths into the one form that every L7
// decision (IP / ACL / route / cache), the access log and the upstream
// request share, so a path cannot be spelled one way to get past a rule and
// be read another way by the backend.
package httppath

import "strings"

// Canonical returns the decoded request path p with its dot segments
// resolved (RFC 3986 section 5.2.4) and runs of '/' merged into one. A
// trailing slash is kept ("/a/b/" stays "/a/b/"; "/a/b/." and "/a/b/c/.."
// become "/a/b/"), and ".." never climbs above the root. An empty path is
// "/" (RFC 9112 section 3.2: an empty path in an absolute-form target means
// the root). Any other path that does not start with '/' (the "*" of
// OPTIONS *, a CONNECT authority) is returned unchanged.
//
// Matching stays case-sensitive: "/ADMIN" and "/admin" are different paths.
// For a case-insensitive backend, write the rule as a regex with (?i).
func Canonical(p string) string {
	if p == "" {
		return "/"
	}
	if p[0] != '/' || isCanonical(p) {
		return p
	}
	segs := strings.Split(p[1:], "/")
	out := make([]string, 0, len(segs))
	trailing := false
	for i, seg := range segs {
		last := i == len(segs)-1
		switch seg {
		case "", ".":
			trailing = last
			continue
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
			trailing = last
			continue
		}
		trailing = false
		out = append(out, seg)
	}
	if len(out) == 0 {
		return "/"
	}
	res := "/" + strings.Join(out, "/")
	if trailing {
		res += "/"
	}
	return res
}

// isCanonical is the allocation-free fast path: true when p (starting with
// '/') has no empty, "." or ".." segment other than a final empty one (the
// trailing slash).
func isCanonical(p string) bool {
	start := 1
	for i := 1; i <= len(p); i++ {
		if i < len(p) && p[i] != '/' {
			continue
		}
		seg := p[start:i]
		if seg == "." || seg == ".." || (seg == "" && i < len(p)) {
			return false
		}
		start = i + 1
	}
	return true
}

// WithoutParams returns the canonical form of p with every segment's
// ";params" part removed ("/admin;x/y" -> "/admin/y", "/a/..;/admin" ->
// "/admin"). Servlet containers and several frameworks drop path
// parameters before routing, so a deny rule has to see this form too.
func WithoutParams(p string) string {
	if !strings.Contains(p, ";") {
		return Canonical(p)
	}
	segs := strings.Split(p, "/")
	for i, seg := range segs {
		if j := strings.IndexByte(seg, ';'); j >= 0 {
			segs[i] = seg[:j]
		}
	}
	return Canonical(strings.Join(segs, "/"))
}
