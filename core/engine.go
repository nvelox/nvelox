package core

import (
	"context"
	"fmt"
	"log"
	"sync"

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
	var wg sync.WaitGroup
	// In a real implementation with gnet, we might run one engine managing multiple listeners
	// or multiple engines. gnet supports multiple listeners.
	// We will start one gnet engine per listener for simplicity in this "HAProxy-like" model
	// where we want distinct loops or just to follow the "distinct gnet listener" plan.

	// Actually gnet can bind to multiple addrs. But they all share the same EventHandler.
	// So we need to map the listener address back to the config in the handler.

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

	// Issue: gnet.Run taking a "proto://addr" only takes one.
	// If we want multiple listeners, we need multiple Run calls in goroutines.

	for _, l := range e.Listeners {
		wg.Add(1)
		go func(conf *ListenerConfig) {
			defer wg.Done()
			e.runListener(conf)
		}(l)
	}

	wg.Wait()
	return nil
}

func (e *Engine) runListener(conf *ListenerConfig) {
	p := "tcp"
	if conf.Protocol == "udp" {
		p = "udp"
	}
	addr := fmt.Sprintf("%s://%s", p, conf.Addr)

	log.Printf("Starting listener %s on %s", conf.Name, addr)

	handler := &ProxyEventHandler{
		engine:   e,
		listener: conf,
	}

	// Multicore true means utilizing generic standard Go scheduler with multiple threads?
	// gnet Multicore=true uses SO_REUSEPORT (on Linux) or multiple reactors.
	err := gnet.Run(handler, addr, gnet.WithMulticore(true), gnet.WithReusePort(true))
	if err != nil {
		log.Printf("Listener %s failed: %v", conf.Name, err)
	}
}
