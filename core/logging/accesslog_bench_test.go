package logging

import "testing"

// BenchmarkAppendAccessHTTP builds one access-log line of an ordinary
// request, as every request served does.
func BenchmarkAppendAccessHTTP(b *testing.B) {
	buf := make([]byte, 0, 512)
	b.ReportAllocs()
	for b.Loop() {
		buf = AppendAccessHTTP(buf[:0], "192.0.2.10", "example.com", "GET", "/api/v1/items?id=42&sort=desc", "HTTP/1.1",
			200, 1024, 0.42, "10.0.0.5:8080",
			"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
			"same-origin", "empty", true, "4bf92f3577b34da6a3ce929d0e0e4736", "site-a")
	}
}
