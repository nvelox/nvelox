package config

import "testing"

// A backend takes connect, response_header and read. Every other timeouts
// field is a listener setting and would do nothing on a backend: refused.
func TestValidation_BackendTimeouts(t *testing.T) {
	cases := []struct {
		name    string
		to      TimeoutConfig
		wantErr []string
	}{
		{"none", TimeoutConfig{}, nil},
		{"all three", TimeoutConfig{Connect: "2s", ResponseHeader: "30s", Read: "5m"}, nil},
		{"zero is no limit", TimeoutConfig{Connect: "0", ResponseHeader: "0", Read: "0"}, nil},
		{"write", TimeoutConfig{Write: "30s"}, []string{"backend be", "timeouts.write is a listener setting", "connect, response_header and read"}},
		{"idle", TimeoutConfig{Idle: "30s"}, []string{"backend be", "timeouts.idle is a listener setting"}},
		{"read_header", TimeoutConfig{ReadHeader: "5s"}, []string{"backend be", "timeouts.read_header is a listener setting"}},
		{"bad connect", TimeoutConfig{Connect: "2 seconds"}, []string{"backend be", "invalid connect timeout"}},
		{"bad response_header", TimeoutConfig{ResponseHeader: "soon"}, []string{"backend be", "invalid response_header timeout"}},
		{"bad read", TimeoutConfig{Read: "1x"}, []string{"backend be", "invalid read timeout"}},
		{"negative read", TimeoutConfig{Read: "-1s"}, []string{"backend be", "invalid read timeout", "negative"}},
		{"negative connect", TimeoutConfig{Connect: "-2s"}, []string{"backend be", "invalid connect timeout", "negative"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := baseCfg(Listener{Name: "web", Bind: ":80", Protocol: "http", Backend: "be"})
			cfg.Backends[0].Timeouts = c.to
			err := validate(cfg)
			if c.wantErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			wantErr(t, err, c.wantErr...)
		})
	}
}

// Listener timeouts: response_header is a backend setting; every value must
// be a duration that is not negative, read_header included (a typo there
// used to switch the header timeout off without a word).
func TestValidation_ListenerTimeouts(t *testing.T) {
	cases := []struct {
		name    string
		to      TimeoutConfig
		wantErr []string
	}{
		{"all", TimeoutConfig{Connect: "2s", ReadHeader: "5s", Read: "30s", Write: "30s", Idle: "2m"}, nil},
		{"zero is no limit", TimeoutConfig{Read: "0", Write: "0", Idle: "0", ReadHeader: "0"}, nil},
		{"response_header", TimeoutConfig{ResponseHeader: "30s"}, []string{"listener web", "timeouts.response_header is a backend setting"}},
		{"bad read_header", TimeoutConfig{ReadHeader: "10 s"}, []string{"listener web", "invalid read_header timeout"}},
		{"negative write", TimeoutConfig{Write: "-1s"}, []string{"listener web", "invalid write timeout", "negative"}},
		{"negative read_header", TimeoutConfig{ReadHeader: "-5s"}, []string{"listener web", "invalid read_header timeout", "negative"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := baseCfg(Listener{Name: "web", Bind: ":80", Protocol: "http", Backend: "be", Timeouts: c.to})
			err := validate(cfg)
			if c.wantErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			wantErr(t, err, c.wantErr...)
		})
	}
}

// response_header and read act on the HTTP path only. A tcp/udp listener on
// a backend that sets one is refused, like backend_tls; an HTTP listener on
// the same backend is fine.
func TestValidation_HTTPOnlyBackendTimeoutsOnL4(t *testing.T) {
	for _, field := range []string{"response_header", "read"} {
		to := TimeoutConfig{ResponseHeader: "30s"}
		if field == "read" {
			to = TimeoutConfig{Read: "30s"}
		}
		for _, proto := range []string{"tcp", "udp"} {
			cfg := baseCfg(Listener{Name: "l4", Bind: ":9000", Protocol: proto, Backend: "be"})
			cfg.Backends[0].Timeouts = to
			wantErr(t, validate(cfg), "listener l4", "backend be sets timeouts."+field, "only http/https listeners")
		}
		cfg := baseCfg(Listener{Name: "web", Bind: ":80", Protocol: "http", Backend: "be"})
		cfg.Backends[0].Timeouts = to
		if err := validate(cfg); err != nil {
			t.Fatalf("http listener, backend %s: %v", field, err)
		}
	}
	// connect works on L4 too.
	cfg := baseCfg(Listener{Name: "l4", Bind: ":9000", Protocol: "tcp", Backend: "be"})
	cfg.Backends[0].Timeouts = TimeoutConfig{Connect: "2s"}
	if err := validate(cfg); err != nil {
		t.Fatalf("tcp listener, backend connect: %v", err)
	}
}

func TestResolveResponseHeader(t *testing.T) {
	for _, c := range []struct {
		val  string
		want string
	}{{"", "1m0s"}, {"0", "0s"}, {"5s", "5s"}} {
		got := TimeoutConfig{ResponseHeader: c.val}.ResolveResponseHeader(60e9)
		if got.String() != c.want {
			t.Fatalf("ResolveResponseHeader(%q) = %v, want %s", c.val, got, c.want)
		}
	}
}
