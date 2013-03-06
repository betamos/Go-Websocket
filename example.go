package main

import (
	"./src/websocket"
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	fmt.Println("Web Sockets server in Go")
	h := websocket.NewHandler()
	websocket.Log = log.New(os.Stdout, "WS log: ", log.LstdFlags)
	http.Handle("/", http.FileServer(http.Dir("web")))
	http.Handle("/myconn", h)
	go http.ListenAndServe("localhost:8080", nil)

	for c, ok := <-h.Conns; ok; c, ok = <-h.Conns {
		// New client c connected

		// Send two messages, first the contents of the file, then a string
		// Note: completely non-blocking
		file, _ := os.Open("example.go")
		c.Out <- file
		c.Out <- bytes.NewBufferString("Hello from server")

		go func() {
			// Close client connection after 3 seconds
			time.Sleep(time.Second * 3)
			c.Close()
		}()

		// Print all messages that arrives
		for r, ok := <-c.In; ok; r, ok = <-c.In {
			io.Copy(os.Stdout, r)
		}
	}
}
