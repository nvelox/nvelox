package core

import (
	"context"
	"fmt"
	"log"

	"nvelox/config"
	"nvelox/core/health"
	"nvelox/core/logging"
	"nvelox/lb"

	"github.com/panjf2000/gnet/v2"
)

type Engine struct {
	gnet.BuiltinEventEngine
	Listeners []*ListenerConfig
	Config    *config.Config
	Balancers map[string]lb.Balancer
	Backends  map[string]*config.Backend
	Checkers  map[string]*health.Checker
}

type ListenerConfig struct {
	Name           string
	Addr           string
	Protocol       string
	ZeroCopy       bool
	DefaultBackend string
	Port           int
}

func NewEngine(cfg *config.Config) *Engine {
	e := &Engine{
		Listeners: make([]*ListenerConfig, 0),
		Config:    cfg,
		Balancers: make(map[string]lb.Balancer),
		Backends:  make(map[string]*config.Backend),
		Checkers:  make(map[string]*health.Checker),
	}
	return e
}

func (e *Engine) Start(ctx context.Context) error {
	// Initialize Backends & Health Checkers
	for i := range e.Config.Backends {
		be := &e.Config.Backends[i]

		// Create Balancer
		balancer := lb.NewBalancer(be.Balance, be.Servers)
		e.Balancers[be.Name] = balancer
		e.Backends[be.Name] = be // Populate map for fast access
		logging.Info("Initialized backend %s with %s balancing", be.Name, be.Balance)

		// Create & Start Health Checker
		if be.HealthCheck.Active.Interval != "" {
			// Ensure a balancer exists for this backend
			balancer, ok := e.Balancers[be.Name]
			if !ok {
				log.Printf("Warning: No balancer found for backend %s, health checks will not update balancer status.", be.Name)
				continue
			}

			checker := health.NewChecker(be.HealthCheck, be) // Pass the backend config directly
			checker.OnStatusChange = func(server string, healthy bool) {
				log.Printf("Health status change for backend %s, server %s: healthy=%t", be.Name, server, healthy)
				balancer.UpdateStatus(server, healthy)
			}
			e.Checkers[be.Name] = checker
			checker.Start()
		}
	}

	// Shared Event Loop Implementation
	// 1. Collect all addresses
	addrs := make([]string, 0, len(e.Listeners))
	listenerMap := make(map[string]*ListenerConfig) // Addr -> Config

	for _, l := range e.Listeners {
		p := "tcp"
		if l.Protocol == "udp" {
			p = "udp"
		}
		// Format: proto://host:port
		fullAddr := fmt.Sprintf("%s://%s", p, l.Addr)
		addrs = append(addrs, fullAddr)

		// Map for lookup in Handler
		// Use "proto:port" as key to avoid collision between TCP/UDP on same port
		// and to handle different bind IPs (0.0.0.0 vs 127.0.0.1) resolving to the same port.
		key := fmt.Sprintf("%s:%d", l.Protocol, l.Port)
		listenerMap[key] = l
		logging.Info("Registering listener %s on %s (Key: %s)", l.Name, fullAddr, key)
	}

	handler := &ProxyEventHandler{
		engine:      e,
		listenerMap: listenerMap,
	}

	logging.Info("Starting Shared Event Loop on %d listeners...", len(addrs))

	// 2. Start Global Engine
	// We establish ONE engine for ALL ports.
	// This invokes Multicore=true so we use NumCPU threads total, regardless of port count.
	err := gnet.Rotate(handler, addrs, gnet.WithMulticore(true), gnet.WithReusePort(true))
	if err != nil {
		return fmt.Errorf("gnet.Rotate failed: %v", err)
	}

	return nil
}

// runListener is deprecated/removed in Shared Loop model
