package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"nvelox/config"
	"nvelox/core"
	"nvelox/core/logging"
)

var (
	// Version is injected at link time by goreleaser:
	//   -ldflags "-X main.Version={{.Tag}}"
	// Plain `go build` with no ldflags leaves this as "dev" so an
	// operator running an unstamped binary sees it immediately.
	Version = "dev"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// SIGHUP reload channel
	reloadCh := make(chan os.Signal, 1)
	signal.Notify(reloadCh, syscall.SIGHUP)

	if err := run(os.Args, ctx, reloadCh); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func run(args []string, ctx context.Context, reloadCh <-chan os.Signal) error {
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

	// Expand port ranges in listeners.
	expandedListeners, err := core.ExpandListeners(cfg.Listeners)
	if err != nil {
		return fmt.Errorf("listener expansion: %w", err)
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

	// Handle SIGHUP reload
	if reloadCh != nil {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-reloadCh:
					logging.Info("Received SIGHUP, reloading configuration from %s", *configPath)
					newCfg, err := config.Load(*configPath)
					if err != nil {
						logging.Error("Config reload failed (validation): %v — keeping current config", err)
						continue
					}
					if err := engine.Reload(newCfg); err != nil {
						logging.Error("Config reload failed (apply): %v — keeping current config", err)
						continue
					}
				}
			}
		}()
	}

	select {
	case <-ctx.Done():
		log.Println("Shutting down...")
		return nil
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

