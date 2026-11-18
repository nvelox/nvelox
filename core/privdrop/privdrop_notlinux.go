//go:build unix && !linux

package privdrop

// threads: the IDs are the process's on these systems, and verify has
// looked at them.
func (t target) threads() error { return nil }
