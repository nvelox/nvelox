//go:build linux

package privdrop

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// After a switch every thread of the process is looked at, not only the
// one that made it: each has its own IDs on Linux.

func TestThreads_OfThisProcess(t *testing.T) {
	// More threads than one: goroutines that hold theirs.
	stop := make(chan struct{})
	defer close(stop)
	for i := 0; i < 4; i++ {
		ready := make(chan struct{})
		go func() {
			runtime.LockOSThread()
			close(ready)
			<-stop
		}()
		<-ready
	}
	if entries, err := os.ReadDir("/proc/self/task"); err != nil || len(entries) < 5 {
		t.Fatalf("the process has %d threads listed (%v), the test needs five and more", len(entries), err)
	}
	me := target{uid: os.Getuid(), gid: os.Getgid()}
	if err := me.threads(); err != nil {
		t.Errorf("the threads of this process, against its own IDs: %v", err)
	}
	if err := (target{uid: os.Getuid() + 1, gid: -1}).threads(); err == nil || !strings.Contains(err.Error(), "uid") {
		t.Errorf("against another uid: %v, want an error that names it", err)
	}
	if err := (target{uid: -1, gid: os.Getgid() + 1}).threads(); err == nil || !strings.Contains(err.Error(), "gid") {
		t.Errorf("against another gid: %v, want an error that names it", err)
	}
	if err := (target{uid: -1, gid: -1}).threads(); err != nil {
		t.Errorf("with nothing to check: %v", err)
	}
}

// A thread that kept other IDs is found, whichever of its four IDs that
// is; one that ended while the list was read is passed over; a list that
// cannot be read is an error, and so is one without a thread.
func TestThreads_OneThatDiffers(t *testing.T) {
	status := func(uid, gid string) string {
		return "Name:\tnvelox\nTgid:\t100\nUid:\t" + uid + "\nGid:\t" + gid + "\nGroups:\t1000\n"
	}
	tasks := func(t *testing.T, files map[string]string) string {
		dir := t.TempDir()
		for tid, content := range files {
			if err := os.MkdirAll(filepath.Join(dir, tid), 0o755); err != nil {
				t.Fatal(err)
			}
			if content == "" {
				continue // a thread that ended: its directory is listed, its file is gone
			}
			if err := os.WriteFile(filepath.Join(dir, tid, "status"), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}
	want := target{uid: 1000, gid: 1000}
	same := status("1000\t1000\t1000\t1000", "1000\t1000\t1000\t1000")
	if err := want.threadsIn(tasks(t, map[string]string{"100": same, "101": same, "102": ""})); err != nil {
		t.Errorf("threads that all switched, and one that ended: %v", err)
	}
	for _, c := range []struct{ what, uid, gid string }{
		{"a real uid of root", "0\t1000\t1000\t1000", "1000\t1000\t1000\t1000"},
		{"an effective uid of root", "1000\t0\t1000\t1000", "1000\t1000\t1000\t1000"},
		{"a saved uid of root", "1000\t1000\t0\t1000", "1000\t1000\t1000\t1000"},
		{"a filesystem uid of root", "1000\t1000\t1000\t0", "1000\t1000\t1000\t1000"},
		{"a saved gid of root", "1000\t1000\t1000\t1000", "1000\t1000\t0\t1000"},
		{"a line that is cut short", "1000\t1000", "1000\t1000\t1000\t1000"},
		{"an ID that is no number", "1000\tx\t1000\t1000", "1000\t1000\t1000\t1000"},
	} {
		err := want.threadsIn(tasks(t, map[string]string{"100": same, "101": status(c.uid, c.gid)}))
		if err == nil || !strings.Contains(err.Error(), "thread 101") {
			t.Errorf("a thread with %s: %v, want an error that names thread 101", c.what, err)
		}
	}
	if err := want.threadsIn(tasks(t, map[string]string{"100": "Name:\tnvelox\n"})); err == nil {
		t.Error("a thread whose IDs are not in its status: no error")
	}
	if err := want.threadsIn(tasks(t, map[string]string{"100": ""})); err == nil {
		t.Error("no thread that could be looked at: no error")
	}
	if err := want.threadsIn(filepath.Join(t.TempDir(), "none")); err == nil {
		t.Error("a list of threads that cannot be read: no error")
	}
	// The check of a switch (verify) includes them: the thread that made
	// the switch has the IDs it switched to, another has not.
	me := target{uid: os.Getuid(), gid: os.Getgid()}
	if err := me.verify(); err != nil {
		t.Fatalf("this process against its own IDs: %v", err)
	}
	mine := status(strings.Repeat(strconv.Itoa(me.uid)+"\t", 4), strings.Repeat(strconv.Itoa(me.gid)+"\t", 4))
	other := status(strings.Repeat(strconv.Itoa(me.uid+1)+"\t", 4), strings.Repeat(strconv.Itoa(me.gid)+"\t", 4))
	taskDir = tasks(t, map[string]string{"100": mine, "101": other})
	defer func() { taskDir = "/proc/self/task" }()
	if err := me.verify(); err == nil || !strings.Contains(err.Error(), "thread 101") {
		t.Errorf("a switch after which one thread has other IDs: %v, want an error that names thread 101", err)
	}
	// Only what was switched is checked.
	if err := (target{uid: 1000, gid: -1}).threadsIn(tasks(t, map[string]string{"100": status("1000\t1000\t1000\t1000", "0\t0\t0\t0")})); err != nil {
		t.Errorf("a switch of the user alone, threads with another group: %v", err)
	}
}
