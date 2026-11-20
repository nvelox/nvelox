//go:build !windows

package config

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// within runs f and returns its error, or fails when f has not returned in
// d: a read that waits for a writer would never return.
func within(t *testing.T, d time.Duration, f func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- f() }()
	select {
	case err := <-done:
		return err
	case <-time.After(d):
		t.Fatalf("still reading after %v", d)
		return nil
	}
}

func mkfifo(t *testing.T, path string) {
	t.Helper()
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("no FIFO here: %v", err)
	}
}

func TestReadNamedFile_Regular(t *testing.T) {
	p := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(p, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := ReadNamedFile(p); err != nil || string(b) != "data" {
		t.Fatalf("ReadNamedFile: %q, %v", b, err)
	}
	if _, err := ReadNamedFile(p + ".missing"); err == nil || !strings.Contains(err.Error(), "no such file") {
		t.Fatalf("a missing file: %v", err)
	}
}

// A FIFO is refused at once, not waited on.
func TestReadNamedFile_FIFO(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fifo")
	mkfifo(t, p)
	err := within(t, 2*time.Second, func() error { _, err := ReadNamedFile(p); return err })
	if err == nil || !strings.Contains(err.Error(), "is a FIFO, not a regular file") {
		t.Fatalf("a FIFO: %v", err)
	}
}

// A device is refused before a byte of it is read.
func TestReadNamedFile_Device(t *testing.T) {
	if _, err := os.Stat("/dev/zero"); err != nil {
		t.Skip("no /dev/zero here")
	}
	err := within(t, 2*time.Second, func() error { _, err := ReadNamedFile("/dev/zero"); return err })
	if err == nil || !strings.Contains(err.Error(), "is a device, not a regular file") {
		t.Fatalf("/dev/zero: %v", err)
	}
}

func TestReadNamedFile_Directory(t *testing.T) {
	if _, err := ReadNamedFile(t.TempDir()); err == nil || !strings.Contains(err.Error(), "is a directory, not a regular file") {
		t.Fatalf("a directory: %v", err)
	}
}

// What a configuration names is read by ReadNamedFile: a key file, an
// included file, a certificate that is a FIFO stops the load at once.
func TestLoad_NamedFilesThatAreFIFOs(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "named.fifo")
	mkfifo(t, fifo)
	load := func(body string) error {
		return within(t, 2*time.Second, func() error {
			p := filepath.Join(dir, "c.yaml")
			if err := os.WriteFile(p, []byte("version: \"2\"\n"+body), 0o644); err != nil {
				return err
			}
			_, err := Load(p)
			return err
		})
	}
	backend := "backends:\n  - name: b\n    servers: [\"127.0.0.1:1\"]\n"
	if err := load("listeners:\n  - name: relay\n    bind: \":7000\"\n    protocol: udp\n    backend: b\n" +
		"    accept_proxy_from: [\"10.0.0.0/8\"]\n    accept_proxy_key_file: \"" + fifo + "\"\n" + backend); err == nil || !strings.Contains(err.Error(), "is a FIFO") {
		t.Fatalf("a key file that is a FIFO: %v", err)
	}

	sub := filepath.Join(dir, "conf.d")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	mkfifo(t, filepath.Join(sub, "a.yaml"))
	if err := load("include: \"conf.d/*.yaml\"\nlisteners:\n  - name: l\n    bind: \":7001\"\n    protocol: tcp\n    backend: b\n" + backend); err == nil || !strings.Contains(err.Error(), "is a FIFO") {
		t.Fatalf("an included file that is a FIFO: %v", err)
	}

	if err := within(t, 2*time.Second, func() error { _, err := LoadKeyPair(fifo, fifo); return err }); err == nil || !strings.Contains(err.Error(), "is a FIFO") {
		t.Fatalf("a certificate that is a FIFO: %v", err)
	}
	if err := within(t, 2*time.Second, func() error { _, err := LoadCertPool(fifo); return err }); err == nil || !strings.Contains(err.Error(), "is a FIFO") {
		t.Fatalf("a CA file that is a FIFO: %v", err)
	}
}

// A FIFO is refused without being opened: opening a FIFO wakes a writer
// that waits on it, as opening a watchdog arms it. The writer here must
// still be waiting after the refusal.
func TestReadNamedFile_NotOpenedBeforeItsTypeIsKnown(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fifo")
	mkfifo(t, p)
	opened := make(chan struct{})
	go func() {
		f, err := os.OpenFile(p, os.O_WRONLY, 0) // waits for a reader
		if err == nil {
			close(opened)
			f.Close()
		}
	}()
	time.Sleep(50 * time.Millisecond)
	if _, err := ReadNamedFile(p); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("a FIFO: %v", err)
	}
	select {
	case <-opened:
		t.Fatal("ReadNamedFile opened the FIFO before refusing it: a writer waiting on it went on")
	case <-time.After(200 * time.Millisecond):
	}
	// Let the writer go.
	if f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NONBLOCK, 0); err == nil {
		<-opened
		f.Close()
	}
}

// A file over maxNamedFile is refused, not read: a sparse one here, so the
// test takes no room.
func TestReadNamedFile_TooLarge(t *testing.T) {
	p := filepath.Join(t.TempDir(), "big")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxNamedFile + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := ReadNamedFile(p); err == nil || !strings.Contains(err.Error(), "larger than the 64 MiB") {
		t.Fatalf("a file of %d bytes: %v", maxNamedFile+1, err)
	}
	if err := os.Truncate(p, maxNamedFile); err != nil {
		t.Fatal(err)
	}
	if b, err := ReadNamedFile(p); err != nil || len(b) != maxNamedFile {
		t.Fatalf("a file of exactly %d bytes: %d bytes, %v", maxNamedFile, len(b), err)
	}
}

// A file that grows past maxNamedFile once it is open (or a file that says
// nothing of its size, as those of /proc) is read no further than that,
// and refused.
func TestReadNamedFile_GrowsAfterTheLook(t *testing.T) {
	p := filepath.Join(t.TempDir(), "grows")
	if err := os.WriteFile(p, []byte("small"), 0o600); err != nil {
		t.Fatal(err)
	}
	defer func(f func(string)) { afterNamedOpen = f }(afterNamedOpen)
	afterNamedOpen = func(path string) {
		if err := os.Truncate(path, maxNamedFile+1); err != nil {
			t.Error(err)
		}
	}
	if _, err := ReadNamedFile(p); err == nil || !strings.Contains(err.Error(), "grew past the 64 MiB") {
		t.Fatalf("a file that grew past %d bytes once open: %v", maxNamedFile, err)
	}
}
