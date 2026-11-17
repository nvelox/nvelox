// http_backend.go — simple HTTP echo backend for testing nvelox examples.
// Usage: go run examples/http_backend.go :8081 "backend-1"
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

func main() {
	addr := ":8081"
	name := "backend"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}
	if len(os.Args) > 2 {
		name = os.Args[2]
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", name)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Hello from %s\n", name)
		fmt.Fprintf(w, "Method: %s\n", r.Method)
		fmt.Fprintf(w, "Path: %s\n", r.URL.Path)
		fmt.Fprintf(w, "Host: %s\n", r.Host)
		for k, vv := range r.Header {
			fmt.Fprintf(w, "Header %s: %s\n", k, strings.Join(vv, ", "))
		}
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "OK")
	})

	log.Printf("[%s] HTTP backend listening on %s", name, addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
