package core

import (
	"context"
	"strings"
	"testing"
	"time"

	"nvelox/config"
)

// TestEngineStart_AdminWithoutKeyFails: an engine whose config enables the
// admin API without a key (a config that bypassed config.Load) refuses to
// start instead of serving the API unauthenticated.
func TestEngineStart_AdminWithoutKeyFails(t *testing.T) {
	e := NewEngine(&config.Config{
		Version: "2",
		Admin:   config.AdminConfig{Enabled: true, Bind: "127.0.0.1:0"},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := e.Start(ctx)
	if err == nil || !strings.Contains(err.Error(), "api_key is required") {
		t.Fatalf("Start with admin enabled and no key: err = %v, want an api_key error", err)
	}
}
