package core

import (
	"context"
	"fmt"
	"log"
	"time"

	"nvelox/config"
	"nvelox/core/health"
	"nvelox/core/logging"
	"nvelox/lb"

	"github.com/lesismal/nbio"
)

type Engine struct {
	TCPEngine *nbio.Engine
	UDPEngine *nbio.Engine
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
	// 1. Initialize Backends & Health Checkers
	e.initBackends()

	// 2. Setup Handler
	handler := NewProxyEventHandler(e)

	// 3. Setup TCP Engine
	tcpAddrs := e.getAddrs("tcp")
	if len(tcpAddrs) > 0 {
		conf := nbio.Config{
			Network:            "tcp",
			Addrs:              tcpAddrs,
			MaxWriteBufferSize: 6 * 1024 * 1024,
		}
		e.TCPEngine = nbio.NewEngine(conf)
		e.TCPEngine.OnOpen(handler.OnOpen)
		e.TCPEngine.OnData(handler.OnData)
		e.TCPEngine.OnClose(handler.OnClose)

		if err := e.TCPEngine.Start(); err != nil {
			return fmt.Errorf("TCP Engine start failed: %v", err)
		}
		logging.Info("NBIO TCP Engine Started on %d listeners", len(tcpAddrs))
	}

	// 4. Setup UDP Engine
	udpAddrs := e.getAddrs("udp")
	if len(udpAddrs) > 0 {
		conf := nbio.Config{
			Network:        "udp",
			Addrs:          udpAddrs,
			UDPReadTimeout: 60 * time.Second,
		}
		e.UDPEngine = nbio.NewEngine(conf)
		e.UDPEngine.OnOpen(handler.OnOpen)
		e.UDPEngine.OnData(handler.OnData)
		e.UDPEngine.OnClose(handler.OnClose)

		if err := e.UDPEngine.Start(); err != nil {
			return fmt.Errorf("UDP Engine start failed: %v", err)
		}
		logging.Info("NBIO UDP Engine Started on %d listeners", len(udpAddrs))
	}

	// 5. Wait for Context
	<-ctx.Done()

	logging.Info("Stopping NBIO Engines...")
	if e.TCPEngine != nil {
		e.TCPEngine.Stop()
	}
	if e.UDPEngine != nil {
		e.UDPEngine.Stop()
	}
	time.Sleep(time.Second)
	return nil
}

func (e *Engine) initBackends() {
	for i := range e.Config.Backends {
		be := &e.Config.Backends[i]
		balancer := lb.NewBalancer(be.Balance, be.Servers)
		e.Balancers[be.Name] = balancer
		e.Backends[be.Name] = be
		logging.Info("Initialized backend %s with %s balancing", be.Name, be.Balance)

		if be.HealthCheck.Active.Interval != "" {
			checker := health.NewChecker(be.HealthCheck, be)
			checker.OnStatusChange = func(server string, healthy bool) {
				log.Printf("Health status change for backend %s, server %s: healthy=%t", be.Name, server, healthy)
				balancer.UpdateStatus(server, healthy)
			}
			e.Checkers[be.Name] = checker
			checker.Start()
		}
	}
}

func (e *Engine) getAddrs(proto string) []string {
	addrs := make([]string, 0)
	for _, l := range e.Listeners {
		if l.Protocol == proto {
			addrs = append(addrs, l.Addr)
			logging.Info("Registering listener %s on %s", l.Name, l.Addr)
		}
	}
	return addrs
}
