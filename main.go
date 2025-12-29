package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"nvelox/config"
	"nvelox/core"
)

func main() {
	version := flag.Bool("version", false, "Print version and exit")
	configPath := flag.String("config", "nvelox.yaml", "Path to configuration file")
	flag.Parse()

	if *version {
		fmt.Println("nvelox v0.1.0")
		os.Exit(0)
	}

	log.Println("Starting Nvelox Server v0.1.0...")

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Expand port ranges in listeners
	// The implementation plan states we should iterate ranges and create distinct listeners.
	expandedListeners := make([]*core.ListenerConfig, 0)

	for _, l := range cfg.Listeners {
		// Parse Bind: "host:port" or "host:start-end" or ":port"
		host, portStr, err := splitHostPort(l.Bind)
		if err != nil {
			log.Printf("Invalid bind address '%s': %v", l.Bind, err)
			continue
		}

		if strings.Contains(portStr, "-") {
			// Range
			parts := strings.Split(portStr, "-")
			start, _ := strconv.Atoi(parts[0])
			end, _ := strconv.Atoi(parts[1])

			for p := start; p <= end; p++ {
				// Copy listener default backend logic for range
				// Check backend to see if it needs port mapping

				// Re-lookup backend to check for implicit IP-only servers?
				// The Handler does dynamic lookup, so we just pass the names.

				expandedListeners = append(expandedListeners, &core.ListenerConfig{
					Name:           fmt.Sprintf("%s-%d", l.Name, p),
					Addr:           fmt.Sprintf("%s:%d", host, p),
					Protocol:       l.Protocol,
					ZeroCopy:       l.ZeroCopy,
					DefaultBackend: l.DefaultBackend,
					Port:           p,
				})
			}
		} else {
			// Single
			p, _ := strconv.Atoi(portStr)
			expandedListeners = append(expandedListeners, &core.ListenerConfig{
				Name:           l.Name,
				Addr:           l.Bind,
				Protocol:       l.Protocol,
				ZeroCopy:       l.ZeroCopy,
				DefaultBackend: l.DefaultBackend,
				Port:           p,
			})
		}
	}

	engine := core.NewEngine(cfg)
	engine.Listeners = expandedListeners

	go func() {
		if err := engine.Start(context.Background()); err != nil {
			log.Fatalf("Engine stopped: %v", err)
		}
	}()

	// Wait for interrupt
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Println("Shutting down...")
}

func splitHostPort(addr string) (string, string, error) {
	// Simple split by last colon
	lastColon := strings.LastIndex(addr, ":")
	if lastColon == -1 {
		return "", "", fmt.Errorf("missing port in address")
	}
	host := addr[:lastColon]
	port := addr[lastColon+1:]
	return host, port, nil
}
