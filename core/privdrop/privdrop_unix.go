//go:build unix

package privdrop

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"slices"
	"strconv"
	"syscall"
)

// target is the identity to switch to; -1 leaves uid or gid unchanged.
type target struct {
	uid, gid int
	groups   []int
}

// Switch changes the process to userName and groupName (either may be
// empty) after handing files to them. It reports what it did in info, or in
// warning why it did nothing: a process that is not root cannot switch and
// keeps running as it is, as nginx does. err is set when the process is root
// and was asked to give root up but could not: nvelox must not keep running
// with root rights it was told to drop.
func Switch(userName, groupName string, files []string) (info, warning string, err error) {
	if userName == "" && groupName == "" {
		return "", "", nil
	}
	t, rerr := resolve(userName, groupName)
	if os.Geteuid() != 0 {
		if rerr == nil && t.matches(os.Geteuid(), os.Getegid()) {
			return "", "", nil
		}
		return "", fmt.Sprintf("server.user / server.group (%s) not applied: nvelox is not running as root, so it stays uid %d gid %d", names(userName, groupName), os.Geteuid(), os.Getegid()), nil
	}
	if rerr != nil {
		return "", "", rerr
	}
	if t.uid == 0 && (t.gid < 0 || t.gid == 0) {
		return "", "", nil // root to root
	}
	for _, f := range files {
		if err := handOver(f, t); err != nil {
			return "", "", err
		}
	}
	if t.gid >= 0 {
		if err := syscall.Setgroups(t.groups); err != nil {
			return "", "", fmt.Errorf("setgroups %v: %w", t.groups, err)
		}
		if err := syscall.Setgid(t.gid); err != nil {
			return "", "", fmt.Errorf("setgid %d: %w", t.gid, err)
		}
	}
	if t.uid >= 0 {
		if err := syscall.Setuid(t.uid); err != nil {
			return "", "", fmt.Errorf("setuid %d: %w", t.uid, err)
		}
	}
	if err := t.verify(); err != nil {
		return "", "", err
	}
	return fmt.Sprintf("switched to %s (uid %d, gid %d)", names(userName, groupName), os.Geteuid(), os.Getegid()), "", nil
}

func (t target) matches(uid, gid int) bool {
	return (t.uid < 0 || t.uid == uid) && (t.gid < 0 || t.gid == gid)
}

// verify checks the switch took effect for real, effective and saved IDs:
// a process that could become root again has not given root up.
func (t target) verify() error {
	if t.uid >= 0 && (os.Getuid() != t.uid || os.Geteuid() != t.uid) {
		return fmt.Errorf("after setuid %d the process runs as uid %d / euid %d", t.uid, os.Getuid(), os.Geteuid())
	}
	if t.gid >= 0 && (os.Getgid() != t.gid || os.Getegid() != t.gid) {
		return fmt.Errorf("after setgid %d the process runs as gid %d / egid %d", t.gid, os.Getgid(), os.Getegid())
	}
	if t.uid > 0 && syscall.Setuid(0) == nil {
		return errors.New("after the switch the process could become root again")
	}
	return nil
}

// handOver gives a log file to the new user so a reopen (SIGUSR1, SIGHUP)
// still works. Only regular files: not a terminal, a pipe or /dev/stdout.
func handOver(path string, t target) error {
	if path == "" {
		return nil
	}
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return nil
	}
	if err := os.Chown(path, t.uid, t.gid); err != nil {
		return fmt.Errorf("handing %s to the new user: %w", path, err)
	}
	return nil
}

// resolve looks the names (or numeric IDs) up. A user brings its primary
// group and supplementary groups; an explicit group replaces the primary.
func resolve(userName, groupName string) (target, error) {
	t := target{uid: -1, gid: -1}
	if userName != "" {
		u, err := lookupUser(userName)
		if err != nil {
			return t, fmt.Errorf("server.user %q: %w", userName, err)
		}
		if t.uid, err = strconv.Atoi(u.Uid); err != nil {
			return t, fmt.Errorf("server.user %q: uid %q: %w", userName, u.Uid, err)
		}
		if t.gid, err = strconv.Atoi(u.Gid); err != nil {
			return t, fmt.Errorf("server.user %q: gid %q: %w", userName, u.Gid, err)
		}
		if ids, err := u.GroupIds(); err == nil {
			for _, id := range ids {
				if n, err := strconv.Atoi(id); err == nil {
					t.groups = append(t.groups, n)
				}
			}
		}
	}
	if groupName != "" {
		g, err := lookupGroup(groupName)
		if err != nil {
			return t, fmt.Errorf("server.group %q: %w", groupName, err)
		}
		if t.gid, err = strconv.Atoi(g.Gid); err != nil {
			return t, fmt.Errorf("server.group %q: gid %q: %w", groupName, g.Gid, err)
		}
		if userName == "" {
			t.groups = nil
		}
	}
	if t.gid >= 0 && !slices.Contains(t.groups, t.gid) {
		t.groups = append([]int{t.gid}, t.groups...)
	}
	return t, nil
}

func lookupUser(name string) (*user.User, error) {
	u, err := user.Lookup(name)
	if err != nil {
		if byID, idErr := user.LookupId(name); idErr == nil {
			return byID, nil
		}
	}
	return u, err
}

func lookupGroup(name string) (*user.Group, error) {
	g, err := user.LookupGroup(name)
	if err != nil {
		if byID, idErr := user.LookupGroupId(name); idErr == nil {
			return byID, nil
		}
	}
	return g, err
}

func names(userName, groupName string) string {
	switch {
	case userName != "" && groupName != "":
		return fmt.Sprintf("user %q, group %q", userName, groupName)
	case userName != "":
		return fmt.Sprintf("user %q", userName)
	default:
		return fmt.Sprintf("group %q", groupName)
	}
}
