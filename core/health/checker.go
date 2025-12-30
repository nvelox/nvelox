package health

import (
	"net"
	"net/http"
	"sync"
	"time"

	"nvelox/config"
	"nvelox/core/logging"
)

// Checker manages health checks for a backend pool.
type Checker struct {
	Config  config.HealthCheckConfig
	Backend *config.Backend

	// Status map: server_ip -> is_healthy
	mu     sync.Mutex
	status map[string]bool

	OnStatusChange func(server string, healthy bool)

	stopCh chan struct{}
}

func NewChecker(cfg config.HealthCheckConfig, backend *config.Backend) *Checker {
	return &Checker{
		Config:  cfg,
		Backend: backend,
		status:  make(map[string]bool),
		stopCh:  make(chan struct{}),
	}
}

func (c *Checker) Start() {
	if c.Config.Active.Interval == "" {
		return // No active checks
	}

	interval, err := time.ParseDuration(c.Config.Active.Interval)
	if err != nil {
		logging.Error("[Health] Invalid interval %s: %v", c.Config.Active.Interval, err)
		return
	}

	go c.loop(interval)
}

func (c *Checker) Stop() {
	close(c.stopCh)
}

func (c *Checker) loop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	logging.Info("[Health] Started active check for %s every %v", c.Backend.Name, interval)

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.checkAll()
		}
	}
}

func (c *Checker) checkAll() {
	var wg sync.WaitGroup
	for _, srv := range c.Backend.Servers {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			healthy := c.probe(addr)
			c.updateStatus(addr, healthy)
		}(srv)
	}
	wg.Wait()
}

func (c *Checker) probe(addr string) bool {
	timeout, _ := time.ParseDuration(c.Config.Active.Timeout)
	if timeout == 0 {
		timeout = 1 * time.Second
	}

	switch c.Config.Active.Type {
	case "http":
		return c.checkHTTP(addr, timeout)
	default:
		return c.checkTCP(addr, timeout)
	}
}

func (c *Checker) checkTCP(addr string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (c *Checker) checkHTTP(addr string, timeout time.Duration) bool {
	client := http.Client{Timeout: timeout}
	// Assuming HTTP for now. Config needs to specify scheme if HTTPS backend.
	// But our backend list is just "IP:port", usually HTTP.
	url := "http://" + addr + c.Config.Active.Path
	resp, err := client.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 400
}

func (c *Checker) updateStatus(addr string, healthy bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	old, exists := c.status[addr]
	if !exists || old != healthy {
		// State changed
		statusStr := "DOWN"
		if healthy {
			statusStr = "UP"
		}
		logging.Info("[Health] Server %s/%s is now %s", c.Backend.Name, addr, statusStr)
		c.status[addr] = healthy

		if c.OnStatusChange != nil {
			c.OnStatusChange(addr, healthy)
		}

		// TODO: Notify Balancer to remove/add server
	}
}
