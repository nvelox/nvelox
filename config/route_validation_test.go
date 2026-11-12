package config

import (
	"strings"
	"testing"
)

// TestValidation_RouteRegexAndFastCGI: a route path_regex or fastcgi
// split_path_info that does not compile or is too long, a fastcgi route
// without document_root, or a script_name that climbs out of it fail the
// config load.
func TestValidation_RouteRegexAndFastCGI(t *testing.T) {
	fcgi := func(f FastCGIConfig) RouteConfig {
		f.Pass = "127.0.0.1:9000"
		return RouteConfig{Match: RouteMatch{PathRegex: `\.php$`}, FastCGI: f}
	}
	tests := []struct {
		name    string
		route   RouteConfig
		wantErr bool
	}{
		{"valid regex route", RouteConfig{Match: RouteMatch{PathRegex: `^/api/(.*)$`}, Backend: "web"}, false},
		{"invalid route path_regex", RouteConfig{Match: RouteMatch{PathRegex: "^/internal/(.*"}, Backend: "web"}, true},
		{"over-long route path_regex", RouteConfig{Match: RouteMatch{PathRegex: "^/" + strings.Repeat("a", 1100)}, Backend: "web"}, true},
		{"valid fastcgi", fcgi(FastCGIConfig{DocumentRoot: "/var/www/html", SplitPathInfo: `^(.+\.php)(/.*)$`, ScriptName: "/index.php"}), false},
		{"fastcgi without document_root", fcgi(FastCGIConfig{}), true},
		{"invalid split_path_info", fcgi(FastCGIConfig{DocumentRoot: "/var/www/html", SplitPathInfo: "^(.+\\.php(/.*)$"}), true},
		{"over-long split_path_info", fcgi(FastCGIConfig{DocumentRoot: "/var/www/html", SplitPathInfo: "(" + strings.Repeat("a", 1100) + ")"}), true},
		{"script_name climbing out", fcgi(FastCGIConfig{DocumentRoot: "/var/www/html", ScriptName: "/../html-old/x.php"}), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Version:  "2",
				Backends: []Backend{{Name: "web", Servers: []string{"10.0.0.1:80"}}},
				Listeners: []Listener{{
					Name: "l1", Bind: ":80", Protocol: "http", Routes: []RouteConfig{tt.route},
				}},
			}
			err := validate(cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
