package main

import (
	"./src/websocket"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

func main() {
	h := websocket.NewHandler()
	go func() {
		for c, ok := <-h.Conns; ok; c, ok = <-h.Conns {
			// Client processing
			fmt.Println("New client", c)
			for r, ok := <-c.In; ok; r, ok = <-c.In {
				// Print messages
				io.Copy(os.Stdout, r)
				c.Close()
			}
			fmt.Println("Client disconnected")
		}
		fmt.Println("No more clients")
	}()

	fmt.Println("Web Sockets in Go")
	http.Handle("/", http.FileServer(http.Dir("web")))
	http.Handle("/myconn", h)
	log.Fatal(http.ListenAndServe("localhost:8080", nil))
}
