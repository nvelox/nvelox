package admin

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"nvelox/core/logging"
	"nvelox/lb"
)

// Server provides a REST API for runtime management.
type Server struct {
	httpServer *http.Server
	balancers  map[string]lb.Balancer
	startTime  time.Time
	apiKey     string
}

// BackendStatus represents a backend's status in the API response.
type BackendStatus struct {
	Name    string   `json:"name"`
	Servers []string `json:"servers"`
}

// StatsResponse is the response for GET /api/v1/stats.
type StatsResponse struct {
	Uptime   string `json:"uptime"`
	Backends int    `json:"backends"`
}

// NewServer creates an admin API server.
func NewServer(bind string, apiKey string, balancers map[string]lb.Balancer) *Server {
	s := &Server{
		balancers: balancers,
		startTime: time.Now(),
		apiKey:    apiKey,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/stats", s.authenticate(s.handleStats))
	mux.HandleFunc("/api/v1/backends", s.authenticate(s.handleBackends))
	mux.HandleFunc("/api/v1/backends/", s.authenticate(s.handleBackendAction))

	s.httpServer = &http.Server{
		Addr:         bind,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	return s
}

// authenticate wraps a handler with API key authentication and localhost enforcement.
func (s *Server) authenticate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Enforce localhost-only if bound to loopback
		if s.isLoopbackBind() {
			clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
			ip := net.ParseIP(clientIP)
			if ip != nil && !ip.IsLoopback() {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}

		// API key authentication (constant-time comparison)
		if s.apiKey != "" {
			key := r.Header.Get("X-API-Key")
			if subtle.ConstantTimeCompare([]byte(key), []byte(s.apiKey)) != 1 {
				logging.Warn("[ADMIN] Unauthorized request from %s", r.RemoteAddr)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}

		next(w, r)
	}
}

func (s *Server) isLoopbackBind() bool {
	host, _, err := net.SplitHostPort(s.httpServer.Addr)
	if err != nil {
		return false
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Start begins listening.
func (s *Server) Start() error {
	if s.apiKey == "" {
		logging.Warn("[ADMIN] API started WITHOUT authentication — set admin.api_key in config")
	}
	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logging.Error("[ADMIN] Server error: %v", err)
		}
	}()
	logging.Info("[ADMIN] API started on %s", s.httpServer.Addr)
	return nil
}

// Stop shuts down the admin server.
func (s *Server) Stop(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	resp := StatsResponse{
		Uptime:   time.Since(s.startTime).Round(time.Second).String(),
		Backends: len(s.balancers),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleBackends(w http.ResponseWriter, r *http.Request) {
	var backends []BackendStatus
	for name := range s.balancers {
		backends = append(backends, BackendStatus{Name: name})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(backends)
}

func (s *Server) handleBackendAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	parts := splitPath(r.URL.Path)
	if len(parts) < 5 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	backendName := parts[3]
	action := parts[4]

	balancer, ok := s.balancers[backendName]
	if !ok {
		http.Error(w, "Backend not found", http.StatusNotFound)
		return
	}

	server := r.URL.Query().Get("server")
	if server == "" {
		http.Error(w, "server query param required", http.StatusBadRequest)
		return
	}

	switch action {
	case "drain":
		balancer.MarkDraining(server)
		logging.Info("[ADMIN] Server %s in %s marked as draining", server, backendName)
	case "enable":
		balancer.UpdateStatus(server, true)
		logging.Info("[ADMIN] Server %s in %s enabled", server, backendName)
	case "disable":
		balancer.UpdateStatus(server, false)
		logging.Info("[ADMIN] Server %s in %s disabled", server, backendName)
	default:
		http.Error(w, "Unknown action", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": action, "server": server})
}

func splitPath(path string) []string {
	var parts []string
	for _, p := range strings.Split(path, "/") {
		if p != "" {
			parts = append(parts, p)
		}
	}
	return parts
}
