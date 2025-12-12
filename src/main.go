package main

import (
	"log"
	"net"
)

func main() {
	port := "1338"
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("[FATAL] Error starting server: %v", err)
	}
	defer listener.Close()

	server := newServer()
	go server.run()

	log.Printf("[STARTUP] IRC Server started on port %s", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[ERROR] Connection error: %v", err)
			continue
		}
		go server.handleConnection(conn)
	}
}
