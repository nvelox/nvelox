package config

import (
	"crypto/tls"
	"fmt"
	"io"
	"io/fs"
)

// ReadNamedFile reads a file the configuration names (an included file, a
// key, a certificate, a CA, an error page). It must be a regular file: a
// FIFO would hold the start, or a reload, until something wrote to it, and
// a device such as /dev/zero would never end. The file is opened without
// waiting (a FIFO opens at once) and checked through the open descriptor,
// so the file checked is the file read.
func ReadNamedFile(path string) ([]byte, error) {
	f, err := openNoWait(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is %s, not a regular file", path, kindOf(fi.Mode()))
	}
	return io.ReadAll(f)
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
