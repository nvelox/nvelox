package core

import (
	"context"
	"nvelox/config"
	"testing"
)

func TestEngine_StartError(t *testing.T) {
	// Setup config with invalid address
	cfg := &config.Config{}
	engine := NewEngine(cfg)

	// Create a listener with an invalid address that gnet cannot bind
	engine.Listeners = append(engine.Listeners, &ListenerConfig{
		Name:     "invalid",
		Addr:     "999.999.999.999:80", // Invalid IP
		Protocol: "tcp",
		Port:     80,
	})

	if err := engine.Start(context.Background()); err == nil {
		t.Error("expected start error for invalid address")
	}
}
