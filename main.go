package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"nvelox/config"
	"nvelox/core"
	"nvelox/core/logging"
	"nvelox/core/pidfile"
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

// preflightConfig is core.Check, the checks of a start that need no socket:
// a variable so a test can prove that --check runs them.
var preflightConfig = core.Check

// setSchedulerSlots is runtime.GOMAXPROCS: a variable so a test can see what
// a config asks for without resizing the scheduler of the test process.
var setSchedulerSlots = runtime.GOMAXPROCS

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
	checkFlag := fs.Bool("check", false, "Check the configuration file and exit: 0 when a start would accept it, 1 with the reason when not")

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

	// --check: everything a start refuses for what is written in the
	// config (the keys, the values, the files it names), and nothing that
	// touches the system: no log file is opened, no port bound, no pid file
	// written. The warnings a start prints are printed here too.
	if *checkFlag {
		if err := preflightConfig(cfg); err != nil {
			return fmt.Errorf("failed to load config: %v", err)
		}
		for _, w := range config.StartupWarnings(cfg) {
			fmt.Fprintf(os.Stderr, "[CONFIG] WARNING: %s\n", w)
		}
		fmt.Printf("%s: configuration is valid\n", *configPath)
		return nil
	}

	// server.workers: how many event loops run. The engine starts one loop
	// per scheduler slot it finds, so the count is set before anything
	// starts a loop. Unset, the runtime's own count stands (the CPU cores
	// the process may use).
	if cfg.Server.Workers > 0 {
		setSchedulerSlots(cfg.Server.Workers)
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
		// server.pid_file: written now that every port is bound (the ID in
		// it is of a process that serves) and before the switch below (the
		// file may live where only root writes).
		if cfg.Server.PidFile != "" {
			removePidFile, err := pidfile.Write(cfg.Server.PidFile)
			if err != nil {
				return fmt.Errorf("server.pid_file: %w", err)
			}
			defer removePidFile()
		}
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
		if n := core.EventLoops(); n > 0 {
			logging.Info("[SERVER] %d event loops", n)
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
					// Read at start only: say so rather than let the
					// new value sit in the file unapplied.
					if newCfg.Server.Workers != cfg.Server.Workers {
						logging.Warn("server.workers changed (%d -> %d): it is read at start, restart nvelox to apply it", cfg.Server.Workers, newCfg.Server.Workers)
					}
					if newCfg.Server.PidFile != cfg.Server.PidFile {
						logging.Warn("server.pid_file changed (%q -> %q): it is read at start, restart nvelox to apply it", cfg.Server.PidFile, newCfg.Server.PidFile)
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
