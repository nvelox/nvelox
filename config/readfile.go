package config

import (
	"crypto/tls"
	"fmt"
	"io"
	"io/fs"
	"os"
)

// maxNamedFile bounds a file the configuration names: certificates, keys,
// included files and error pages are far smaller.
const maxNamedFile = 64 << 20

// afterNamedOpen runs once ReadNamedFile has checked the open file, before
// it reads it: a test makes the file grow there.
var afterNamedOpen = func(path string) {}

// ReadNamedFile reads a file the configuration names (an included file, a
// key, a certificate, a CA, an error page). It must be a regular file: a
// FIFO would hold the start, or a reload, until something wrote to it, and
// a device such as /dev/zero would never end. Its type is looked at before
// it is opened, because opening some devices does something (a watchdog
// arms, a tape rewinds); then again on the open file, which must be the
// file looked at, so that the file read is the file checked. It is opened
// without waiting (a FIFO opens at once) and read up to maxNamedFile.
func ReadNamedFile(path string) ([]byte, error) {
	before, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if err := namedFileOK(path, before); err != nil {
		return nil, err
	}
	f, err := openNoWait(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if err := namedFileOK(path, fi); err != nil {
		return nil, err
	}
	if !os.SameFile(before, fi) {
		return nil, fmt.Errorf("%s changed while it was opened", path)
	}
	afterNamedOpen(path)
	b, err := io.ReadAll(io.LimitReader(f, maxNamedFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxNamedFile {
		// It grew since it was looked at, or says nothing of its size (a
		// file of /proc): what is read is bounded all the same.
		return nil, fmt.Errorf("%s grew past the %d MiB a file the configuration names may be while it was read", path, maxNamedFile>>20)
	}
	return b, nil
}

// namedFileOK: a regular file of maxNamedFile bytes at most.
func namedFileOK(path string, fi fs.FileInfo) error {
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is %s, not a regular file", path, kindOf(fi.Mode()))
	}
	if fi.Size() > maxNamedFile {
		return fmt.Errorf("%s is larger than the %d MiB a file the configuration names may be", path, maxNamedFile>>20)
	}
	return nil
}

// LoadKeyPair is tls.LoadX509KeyPair, the two files read by ReadNamedFile.
func LoadKeyPair(certFile, keyFile string) (tls.Certificate, error) {
	certPEM, err := ReadNamedFile(certFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM, err := ReadNamedFile(keyFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

// kindOf names what a file that is not regular is.
func kindOf(m fs.FileMode) string {
	switch {
	case m.IsDir():
		return "a directory"
	case m&fs.ModeNamedPipe != 0:
		return "a FIFO"
	case m&fs.ModeSocket != 0:
		return "a socket"
	case m&fs.ModeDevice != 0:
		return "a device"
	}
	return "a special file"
}
