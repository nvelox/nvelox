//go:build unix

package privdrop

import (
	"os"
	"os/user"
	"strconv"
	"strings"
	"testing"
)

func TestSwitch_NothingSet(t *testing.T) {
	if info, warning, err := Switch("", "", nil); info != "" || warning != "" || err != nil {
		t.Fatalf("no user, no group: got %q %q %v", info, warning, err)
	}
}

// A process that is not root cannot switch: it keeps running as it is and
// says so (nginx behaves the same), and naming the user it already runs as
// is no change at all.
func TestSwitch_NotRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("runs as root")
	}
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	if info, warning, err := Switch(me.Username, "", nil); info != "" || warning != "" || err != nil {
		t.Fatalf("switch to the current user: got %q %q %v", info, warning, err)
	}
	for _, name := range []string{"root", "nvelox-no-such-user"} {
		info, warning, err := Switch(name, "", nil)
		if err != nil || info != "" || !strings.Contains(warning, "not running as root") {
			t.Errorf("Switch(%q) as non-root: got %q %q %v, want a warning", name, info, warning, err)
		}
	}
	if os.Geteuid() != mustAtoi(t, me.Uid) {
		t.Fatal("uid changed")
	}
}

func TestResolve(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	uid, gid := mustAtoi(t, me.Uid), mustAtoi(t, me.Gid)
	for _, name := range []string{me.Username, me.Uid} {
		got, err := resolve(name, "")
		if err != nil || got.uid != uid || got.gid != gid || got.groups[0] != gid && !contains(got.groups, gid) {
			t.Errorf("resolve(%q): %+v %v, want uid %d gid %d with gid among the groups", name, got, err, uid, gid)
		}
	}
	g, err := user.LookupGroupId(me.Gid)
	if err != nil {
		t.Skip(err)
	}
	got, err := resolve("", g.Name)
	if err != nil || got.uid != -1 || got.gid != gid || len(got.groups) != 1 || got.groups[0] != gid {
		t.Errorf("resolve(group %q only): %+v %v, want uid -1, gid %d, groups [%d]", g.Name, got, err, gid, gid)
	}
	if _, err := resolve("nvelox-no-such-user", ""); err == nil || !strings.Contains(err.Error(), "server.user") {
		t.Errorf("unknown user: err %v", err)
	}
	if _, err := resolve("", "nvelox-no-such-group"); err == nil || !strings.Contains(err.Error(), "server.group") {
		t.Errorf("unknown group: err %v", err)
	}
}

func contains(s []int, v int) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func mustAtoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}
