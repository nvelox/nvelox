package main

import (
	"context"
	"io"
	"log"
	"net"
	"os"
)

func main() {
	addr := ":8081"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}
	if err := run(addr, context.Background()); err != nil {
		log.Fatal(err)
	}
}

func run(addr string, ctx context.Context) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer l.Close()
	log.Printf("Mock backend listening on %s", l.Addr())

	go func() {
		<-ctx.Done()
		l.Close()
	}()

	for {
		conn, err := l.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				log.Println("Accept error:", err)
				continue
			}
		}
		go handle(conn)
	}
}

func handle(c net.Conn) {
	defer c.Close()
	log.Printf("Backend accepted: %s", c.RemoteAddr())

	buf := make([]byte, 1024)
	for {
		n, err := c.Read(buf)
		if n > 0 {
			log.Printf("Backend received %d bytes: %q", n, buf[:n])
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("Backend read error: %v", err)
			}
			break
		}
	}
	log.Printf("Backend connection closed: %s", c.RemoteAddr())
}
