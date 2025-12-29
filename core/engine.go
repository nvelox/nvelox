package core

import (
	"context"
	"fmt"
	"log"
	"sync"

	"nvelox/config"
	"nvelox/lb"

	"github.com/panjf2000/gnet/v2"
)

type Engine struct {
	gnet.BuiltinEventEngine
	Listeners []*ListenerConfig
	Balancers map[string]lb.Balancer
	Backends  map[string]*config.Backend
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
	balancers := make(map[string]lb.Balancer)
	backends := make(map[string]*config.Backend)

	for _, b := range cfg.Backends {
		balancers[b.Name] = lb.NewBalancer(b.Balance, b.Servers)
		backends[b.Name] = &b // Store pointer to loop variable is incorrect if we don't copy, but here loop var is value copy so address of it... wait.
		// range over slice value returns copy. taking address of 'b' takes address of local var. DANGER.
		// Need to copy.
		bk := b
		backends[b.Name] = &bk
	}

	e := &Engine{
		Listeners: make([]*ListenerConfig, 0),
		Balancers: balancers,
		Backends:  backends,
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
