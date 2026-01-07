package integration

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"nvelox/config"
	"nvelox/core"
	"nvelox/core/logging"
)

func TestConfigIncludeAndBackendInit(t *testing.T) {
	// 1. Create Temp Dir
	tmpDir, err := os.MkdirTemp("", "nvelox_config_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Init logging to avoid panic
	logging.Init("debug", "", "")

	// 2. Create Listeners Config (Main)
	mainConfig := fmt.Sprintf(`
version: "2"
server:
  user: "test"
logging:
  level: "debug"
include: "%s/*.yaml"
listeners:
  - name: "l1"
    bind: ":9999"
    protocol: "tcp"
    default_backend: "b1"
`, tmpDir)
	mainPath := filepath.Join(tmpDir, "nvelox.yaml")
	if err := os.WriteFile(mainPath, []byte(mainConfig), 0644); err != nil {
		t.Fatal(err)
	}

	// 3. Create Backend Config (Included) - invalid version to prove we don't check sub-config version,
	// or valid "2" to prove it works. Let's try NO version, as user likely has.
	backendConfig := `
backends:
  - name: "b1"
    balance: "roundrobin"
    servers:
      - "127.0.0.1:8080"
`
	includePath := filepath.Join(tmpDir, "backend.yaml")
	if err := os.WriteFile(includePath, []byte(backendConfig), 0644); err != nil {
		t.Fatal(err)
	}

	// 4. Load Config
	cfg, err := config.Load(mainPath)
	if err != nil {
		t.Fatalf("config.Load failed: %v", err)
	}

	// 5. Verify Backend Loaded
	found := false
	for _, b := range cfg.Backends {
		if b.Name == "b1" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("Backend 'b1' not found in loaded config")
	}

	// 6. Verify Validate Passed (Implicit in Load)

	// 7. Initialize Engine
	engine := core.NewEngine(cfg)
	// Mock Listeners
	engine.Listeners = []*core.ListenerConfig{
		{Name: "l1", Addr: ":9999", Protocol: "tcp", DefaultBackend: "b1"},
	}

	// 8. Run initBackends (manually triggering internal method logic by mocking)
	// We can't call private initBackends, but we can call Start() with a canceled context
	// or check public state?
	// NewProxyEventHandler access e.Balancers.
	// Actually, Engine struct fields are public. We can inspect engine.Balancers AFTER Start calls initBackends.

	// Create a goroutine for Start because it blocks
	ctx, cancel := context.WithCancel(context.Background())
	// Cancel immediately? No, Start needs to run initBackends.
	// initBackends is first.
	// But Start will start NBIO listeners.
	// We handle that by letting it fail on bind or just run briefly.

	errCh := make(chan error)
	go func() {
		// Mock getAddrs to return empty so NBIO doesn't start actual sockets?
		// No, getAddrs uses e.Listeners.
		// We set engine.Listeners.
		// We can set Address to random high port.
		if err := engine.Start(ctx); err != nil {
			errCh <- err
		}
		close(errCh)
	}()

	// Wait a moment for initBackends to run
	time.Sleep(100 * time.Millisecond)
	cancel() // Stop engine
	<-errCh

	// 9. Check Balancers Map
	balancer, ok := engine.Balancers["b1"]
	if !ok {
		t.Fatal("Balancer 'b1' not found in engine map")
	}
	if balancer == nil {
		t.Fatal("Balancer 'b1' is nil")
	}
	t.Log("Balancer found successfully")
}
