package core

import (
	"nvelox/config"
	"nvelox/core/sticky"
	"nvelox/lb"
)

// backendView is an immutable snapshot of the backend maps that request paths
// read: the L4 TCP, TLS and UDP handlers, the HTTP sites and the admin API.
//
// A reload rebuilds the engine's own maps (Balancers, Backends, ConnLimiters,
// StickyStores) under reloadMu while connections are being served. Those maps
// used to be read by request goroutines with no lock, so a SIGHUP under traffic
// could end the process with "fatal error: concurrent map read and map write"
// (seen in production on 2026-10-22). Writers now publish a fresh copy after
// every change; readers only ever load a published copy, which nobody writes
// again. HTTP sites take the view current when they are built, and Reload
// rebuilds every site after it publishes.
type backendView struct {
	Balancers    map[string]lb.Balancer
	Backends     map[string]*config.Backend
	ConnLimiters map[string]*ConnLimiter
	StickyStores map[string]*sticky.Store
}

// publishBackends stores a copy of the engine's backend maps as the current
// view. Call it (under reloadMu) after every change to those maps.
func (e *Engine) publishBackends() {
	v := &backendView{
		Balancers:    make(map[string]lb.Balancer, len(e.Balancers)),
		Backends:     make(map[string]*config.Backend, len(e.Backends)),
		ConnLimiters: make(map[string]*ConnLimiter, len(e.ConnLimiters)),
		StickyStores: make(map[string]*sticky.Store, len(e.StickyStores)),
	}
	for k, b := range e.Balancers {
		v.Balancers[k] = b
	}
	for k, b := range e.Backends {
		v.Backends[k] = b
	}
	for k, c := range e.ConnLimiters {
		v.ConnLimiters[k] = c
	}
	for k, s := range e.StickyStores {
		v.StickyStores[k] = s
	}
	e.view.Store(v)
}

// backends returns the current view: empty (never nil) before the first
// publish.
func (e *Engine) backends() *backendView {
	if v := e.view.Load(); v != nil {
		return v
	}
	return &backendView{}
}
