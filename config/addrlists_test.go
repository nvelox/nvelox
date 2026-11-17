package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeAddrListConfig(t *testing.T, listenerExtra string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "c.yaml")
	cfg := "version: \"2\"\nlisteners:\n  - name: w\n    bind: \":18080\"\n    protocol: http\n    backend: b\n" + listenerExtra +
		"backends:\n  - name: b\n    servers: [\"127.0.0.1:1\"]\n"
	if err := os.WriteFile(p, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestLoad_RejectsInvalidAddrLists (Low): an entry of ip_allowlist,
// ip_denylist, trusted_proxies or an ACL rule's source_ip that is not an IP
// or CIDR fails the load (it used to be dropped silently when the listener
// was built).
func TestLoad_RejectsInvalidAddrLists(t *testing.T) {
	cases := map[string]string{
		"ip_allowlist":    "    ip_allowlist: [\"10.0.0.0/33\"]\n",
		"ip_denylist":     "    ip_denylist: [\"bogus\"]\n",
		"trusted_proxies": "    trusted_proxies: [\"10.0.0.0/8\", \"10.1.0.0/40\"]\n",
		"acl 0 source_ip": "    acl:\n      - match: {source_ip: [\"256.0.0.1\"], path_prefix: /admin}\n        action: allow\n",
	}
	for field, extra := range cases {
		_, err := Load(writeAddrListConfig(t, extra))
		if err == nil || !strings.Contains(err.Error(), field) {
			t.Errorf("%s: Load err = %v, want an error naming the field", field, err)
		}
	}
}

func TestLoad_AcceptsValidAddrLists(t *testing.T) {
	extra := "    ip_allowlist: [\"10.0.0.0/8\", \"192.0.2.7\", \" 2001:db8::/32 \", \"0.0.0.0/0\"]\n" +
		"    ip_denylist: [\"::1\"]\n" +
		"    trusted_proxies: [\"173.245.48.0/20\", \"2400:cb00::/32\"]\n" +
		"    acl:\n      - match: {source_ip: [\"10.10.10.0/24\"], path_regex: \"^/admin(/|$)\"}\n        action: allow\n"
	if _, err := Load(writeAddrListConfig(t, extra)); err != nil {
		t.Fatalf("Load: %v", err)
	}
}
