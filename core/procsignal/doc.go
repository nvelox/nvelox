// Package procsignal holds the signals nvelox's main loop handles besides
// SIGINT and SIGTERM. They differ per OS (Windows has no SIGUSR1), and they
// live here rather than in package main so that main.go still builds on its
// own: the README, the Dockerfile and deploy tooling run
// `go build -o nvelox main.go`, which compiles that one file.
package procsignal
