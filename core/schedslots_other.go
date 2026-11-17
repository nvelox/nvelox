//go:build !linux

package core

// SpareSchedulerSlots does nothing where there are no event loops.
func SpareSchedulerSlots() {}
