//go:build !linux

package core

func stFastUDPSessions(*Engine) []stUDPSession { return nil }
