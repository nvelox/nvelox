//go:build linux

package privdrop

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strconv"
)

// On Linux a thread has its own user and group IDs. The switch goes to
// every thread the Go runtime started (the event loops' among them); a
// thread it does not know of would keep the IDs it had. So after the
// switch each thread of the process is looked at, as the kernel lists
// them: all four of its user IDs, and of its group IDs, are to be the ones
// switched to.

// taskDir is where the kernel lists the threads of the process. A variable
// for the tests only.
var taskDir = "/proc/self/task"

// threads checks every thread of the process against t.
func (t target) threads() error {
	return t.threadsIn(taskDir)
}

func (t target) threadsIn(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("after the switch the threads of the process cannot be looked at: %w", err)
	}
	seen := 0
	for _, e := range entries {
		status, err := os.ReadFile(dir + "/" + e.Name() + "/status")
		if errors.Is(err, os.ErrNotExist) {
			continue // a thread that ended meanwhile
		}
		if err != nil {
			return fmt.Errorf("after the switch thread %s of the process cannot be looked at: %w", e.Name(), err)
		}
		if err := t.checkStatus(status); err != nil {
			return fmt.Errorf("after the switch thread %s of the process: %w", e.Name(), err)
		}
		seen++
	}
	if seen == 0 {
		return errors.New("after the switch no thread of the process could be looked at")
	}
	return nil
}

// checkStatus checks the Uid and Gid lines of a thread's status file: the
// real, effective, saved and filesystem IDs, in that order.
func (t target) checkStatus(status []byte) error {
	for _, c := range [...]struct {
		key  string
		want int
		what string
	}{{"Uid:", t.uid, "uid"}, {"Gid:", t.gid, "gid"}} {
		if c.want < 0 {
			continue
		}
		ids, ok := statusIDs(status, c.key)
		if !ok {
			return fmt.Errorf("its %s cannot be read", c.what)
		}
		for _, id := range ids {
			if id != c.want {
				return fmt.Errorf("runs with %s %v (real, effective, saved, filesystem), want %d", c.what, ids, c.want)
			}
		}
	}
	return nil
}

// statusIDs returns the four numbers of the line of status that begins
// with key.
func statusIDs(status []byte, key string) (ids [4]int, ok bool) {
	for _, line := range bytes.Split(status, []byte("\n")) {
		if !bytes.HasPrefix(line, []byte(key)) {
			continue
		}
		f := bytes.Fields(line[len(key):])
		if len(f) != 4 {
			return ids, false
		}
		for i := range f {
			n, err := strconv.Atoi(string(f[i]))
			if err != nil {
				return ids, false
			}
			ids[i] = n
		}
		return ids, true
	}
	return ids, false
}
