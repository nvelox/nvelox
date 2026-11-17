package main

import (
	"context"
	"fmt"
	"net"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		panic("port required")
	}
	if err := run(os.Args[1], context.Background()); err != nil {
		panic(err)
	}
}

func run(port string, ctx context.Context) error {
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return err
	}
	defer ln.Close()

	fmt.Printf("Backend listening on %s\n", port)

	// Accept loop
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			// Check if closed
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}
		go handle(conn, port)
	}
}

func handle(conn net.Conn, port string) {
	defer conn.Close()
	conn.Write([]byte("Backend-" + port))
}
