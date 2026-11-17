package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"nvelox/config"
	"nvelox/core"
	"nvelox/core/logging"
	"nvelox/core/privdrop"
	"nvelox/core/procsignal"
)

var (
	// Version is injected at link time by goreleaser:
	//   -ldflags "-X main.Version={{.Tag}}"
	// Plain `go build` with no ldflags leaves this as "dev" so an
	// operator running an unstamped binary sees it immediately.
	Version = "dev"
)

// shutdownMargin is what the wait for the engine to stop, after SIGINT or
// SIGTERM, allows beyond server.shutdown_timeout (the time the HTTP
// requests in flight get). The engine's other limits come to less (5 s for
// the admin API, 30 s for the L4 handlers to return): past the margin a
// stop that hangs still ends the process.
const shutdownMargin = 50 * time.Second

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	// The first SIGINT or SIGTERM starts the shutdown, which lets the
	// requests in flight finish. From then on the two signals have their
	// usual effect again: a second one ends the process at once.
	go func() {
		<-ctx.Done()
		stop()
	}()

	// SIGHUP: reopen the log files and reload the config.
	// SIGUSR1: reopen the log files (logrotate postrotate).
	reloadCh := make(chan os.Signal, 4)
	signal.Notify(reloadCh, procsignal.Control...)

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
	// Stamp this gateway's identity on every access-log line (gw=<id>) so a
	// request can be attributed to the gateway that first received it. Empty
	// gateway_id falls back to os.Hostname() inside SetGateway.
	logging.SetGateway(cfg.Server.GatewayID)
	logging.Info("Nvelox Server %s starting...", Version)
	logging.Info("Loaded configuration from %s", *configPath)
	// Keys that do nothing and settings that expose something: say so loudly
	// on stderr (the error log under systemd) whatever the log level.
	for _, w := range config.StartupWarnings(cfg) {
		fmt.Fprintf(os.Stderr, "[CONFIG] WARNING: %s\n", w)
	}

	// Expand port ranges in listeners.
	expandedListeners, err := core.ExpandListeners(cfg.Listeners)
	if err != nil {
		return fmt.Errorf("listener expansion: %w", err)
	}

	engine := core.NewEngine(cfg)
	engine.Listeners = expandedListeners
	// Bind as root, serve only as server.user: nothing is answered before
	// the switch below.
	engine.HoldServing()

	errCh := make(chan error, 1)
	go func() {
		if err := engine.Start(ctx); err != nil {
			errCh <- err
		}
		close(errCh)
	}()

	// Once every port is bound and the log files are open, switch to
	// server.user / server.group. A root process that cannot give root up
	// stops here rather than run with rights it was told to drop.
	select {
	case <-engine.Ready():
		info, warning, err := privdrop.Switch(cfg.Server.User, cfg.Server.Group, logging.HandOver)
		if err != nil {
			return fmt.Errorf("server.user / server.group: %w", err)
		}
		if warning != "" {
			fmt.Fprintf(os.Stderr, "[CONFIG] WARNING: %s\n", warning)
		}
		if info != "" {
			logging.Info("[SERVER] %s", info)
		}
		engine.Serve()
	case err, ok := <-errCh:
		if ok && err != nil && err != context.Canceled {
			return fmt.Errorf("engine stopped: %v", err)
		}
		return nil
	case <-ctx.Done():
		return nil
	}

	// Handle SIGHUP (reopen logs + reload) and SIGUSR1 (reopen logs).
	if reloadCh != nil {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case sig := <-reloadCh:
					// Reopen the log files on either signal, before the
					// reload: logrotate may send either one, and a reload
					// that fails validation must not leave nvelox writing to
					// the rotated file.
					reopenErr := logging.Reopen()
					if reopenErr != nil {
						logging.Error("Log reopen failed: %v — still writing to the previous log files", reopenErr)
					}
					if procsignal.Reopen != nil && sig == procsignal.Reopen {
						if reopenErr == nil {
							logging.Info("Received SIGUSR1, log files reopened")
						}
						continue
					}
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
		// The engine stops on the same context: it accepts nothing new, lets
		// the requests in flight finish within its limits, closes the rest
		// and returns. Returning before it has would end the process, and
		// with it every request still being answered.
		limit := engine.ShutdownTimeout() + shutdownMargin
		select {
		case err := <-errCh:
			if err != nil && err != context.Canceled {
				return fmt.Errorf("engine stopped: %v", err)
			}
		case <-time.After(limit):
			logging.Error("Shutdown did not finish within %v: exiting", limit)
		}
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
