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
	"nvelox/core/logging"
)

var (
	// Version is injected by build flags: -ldflags "-X main.Version=vX.Y.Z"
	Version = "v0.2.1"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(os.Args, ctx); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func run(args []string, ctx context.Context) error {
	fs := flag.NewFlagSet("nvelox", flag.ContinueOnError)
	versionFlag := fs.Bool("version", false, "Print version and exit")
	configPath := fs.String("config", "nvelox.yaml", "Path to configuration file")

	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	if *versionFlag {
		fmt.Printf("nvelox %s\n", Version)
		return nil
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %v", err)
	}

	// Init Logger
	if err := logging.Init(cfg.Logging.Level, cfg.Logging.AccessLog, cfg.Logging.ErrorLog); err != nil {
		return fmt.Errorf("failed to init logger: %v", err)
	}
	logging.Info("Nvelox Server %s starting...", Version)
	logging.Info("Loaded configuration from %s", *configPath)

	// Expand port ranges in listeners
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

	errCh := make(chan error, 1)
	go func() {
		if err := engine.Start(ctx); err != nil {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		log.Println("Shutting down...")
		return nil // Success exit (cancelled by context)
	case err := <-errCh:
		if err == context.Canceled {
			return nil
		}
		if err != nil {
			return fmt.Errorf("engine stopped: %v", err)
		}
		return nil
	}
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
