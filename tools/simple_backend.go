package main

import (
	"fmt"
	"net"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		panic("port required")
	}
	port := os.Args[1]
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Backend listening on %s\n", port)
	for {
		conn, err := ln.Accept()
		if err != nil {
			break
		}
		conn.Write([]byte("Backend-" + port))
		conn.Close()
	}
}
