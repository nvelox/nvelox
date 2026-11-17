package health

import (
	"context"
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

	// proxyOnce / proxyTransport: the transport of the HTTP checks of a
	// send_proxy_v2 backend (see localProxyHeader).
	proxyOnce      sync.Once
	proxyTransport *http.Transport
}

// localProxyHeader is a PROXY protocol v2 header with the LOCAL command: the
// sender speaks for itself, there is no client to name. A backend with
// send_proxy_v2 expects a PROXY header at the start of every connection, so
// its HTTP health checks send this one: without it the check's request
// would be read as a connection that broke the protocol and fail, however
// healthy the server is.
//
// A TCP check sends nothing, with or without send_proxy_v2: it connects
// and closes, which every server takes as a connection that brought
// nothing. A header there would make a server that serves LOCAL
// connections (another nvelox that trusts this one as a relay does) open a
// session for each check: a backend connection and an access record,
// every interval.
var localProxyHeader = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x20, 0x00, 0x00, 0x00}

// sendsProxy reports whether the backend's connections start with a PROXY
// header.
func (c *Checker) sendsProxy() bool { return c.Backend != nil && c.Backend.SendProxyV2 }

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
	c.proxyOnce.Do(func() {}) // no transport is made from here on
	if t := c.proxyTransport; t != nil {
		t.CloseIdleConnections()
	}
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

// httpTransport returns the transport of the backend's HTTP checks: the
// default one, or for a send_proxy_v2 backend one of the checker's own
// whose connections start with a LOCAL header.
func (c *Checker) httpTransport() http.RoundTripper {
	if !c.sendsProxy() {
		return http.DefaultTransport
	}
	c.proxyOnce.Do(func() {
		t := http.DefaultTransport.(*http.Transport).Clone()
		dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
		t.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			if d, ok := ctx.Deadline(); ok {
				conn.SetWriteDeadline(d)
			}
			if _, err := conn.Write(localProxyHeader); err != nil {
				conn.Close()
				return nil, err
			}
			conn.SetWriteDeadline(time.Time{})
			return conn, nil
		}
		c.proxyTransport = t
	})
	if c.proxyTransport == nil {
		return http.DefaultTransport // stopped before its first check
	}
	return c.proxyTransport
}

func (c *Checker) checkHTTP(addr string, timeout time.Duration) bool {
	client := http.Client{Timeout: timeout, Transport: c.httpTransport()}
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
	}
}
