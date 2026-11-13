//go:build !unix

package logging

import "os"

const noFollow = 0

func isSymlinkRefusal(error) bool { return false }

func runningAsRoot() bool { return false }

func linkCount(os.FileInfo) uint64 { return 1 }
