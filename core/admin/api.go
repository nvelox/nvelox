package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"nvelox/core/logging"
	"nvelox/lb"
)

// Server provides a REST API for runtime management.
type Server struct {
	httpServer *http.Server
	balancers  map[string]lb.Balancer
	startTime  time.Time
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
func NewServer(bind string, balancers map[string]lb.Balancer) *Server {
	s := &Server{
		balancers: balancers,
		startTime: time.Now(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/stats", s.handleStats)
	mux.HandleFunc("/api/v1/backends", s.handleBackends)
	mux.HandleFunc("/api/v1/backends/", s.handleBackendAction)

	s.httpServer = &http.Server{
		Addr:    bind,
		Handler: mux,
	}

	return s
}

// Start begins listening.
func (s *Server) Start() error {
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

	// Parse: /api/v1/backends/{name}/drain
	// Simple path parsing
	path := r.URL.Path
	// Expected: /api/v1/backends/{name}/{action}
	parts := splitPath(path)
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

	switch action {
	case "drain":
		// Drain a specific server
		server := r.URL.Query().Get("server")
		if server == "" {
			http.Error(w, "server query param required", http.StatusBadRequest)
			return
		}
		balancer.MarkDraining(server)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "draining", "server": server})

	case "enable":
		server := r.URL.Query().Get("server")
		if server == "" {
			http.Error(w, "server query param required", http.StatusBadRequest)
			return
		}
		balancer.UpdateStatus(server, true)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "enabled", "server": server})

	case "disable":
		server := r.URL.Query().Get("server")
		if server == "" {
			http.Error(w, "server query param required", http.StatusBadRequest)
			return
		}
		balancer.UpdateStatus(server, false)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "disabled", "server": server})

	default:
		http.Error(w, "Unknown action", http.StatusBadRequest)
	}
}

func splitPath(path string) []string {
	var parts []string
	for _, p := range split(path, '/') {
		if p != "" {
			parts = append(parts, p)
		}
	}
	return parts
}

func split(s string, sep byte) []string {
	var result []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			result = append(result, s[start:i])
			start = i + 1
		}
	}
	result = append(result, s[start:])
	return result
}
