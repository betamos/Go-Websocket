package main

import (
	"fmt"
	//	"net"
	"crypto/sha1"
	//"encoding/base64"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"strings"
)

const (
	guid           = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	secWSKeyLength = 16
)

var secWSKeyMalformedError = errors.New("Malformed Sec-WebSocket-Key")

func main() {
	fmt.Println("Web socketaaa")
	http.Handle("/", http.FileServer(http.Dir("web")))
	http.HandleFunc("/myconn", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println(r)
		// Check r.ProtoMajor and r.ProtoMinor
		// TODO: Response status
		// Check headers
		if r.Header.Get("Upgrade") != "websocket" {
			log.Fatal("bajs")
		} else if r.Header.Get("Connection") != "Upgrade" {
			log.Fatal("kiss")
		}
		// Base64 encoded key
		secWSKey := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key"))

		secWSAccept, err := validateSecWebSocketKey(secWSKey)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
		}
		fmt.Println(secWSAccept)
		w.Header().Set("Upgrade", "websocket")
		w.Header().Set("Connection", "Upgrade")
		w.Header().Set("Sec-WebSocket-Accept", secWSAccept)
		w.WriteHeader(http.StatusSwitchingProtocols)
	})
	log.Fatal(http.ListenAndServe("localhost:8080", nil))
}

// Validate and return the Sec-WebSocket-Accept calculated by the
// Sec-WebSocket-Key value.
func validateSecWebSocketKey(key string) (secWSAccept string, err error) {
	if decodedKey, _ := base64.StdEncoding.DecodeString(key); err != nil || len(decodedKey) != secWSKeyLength {
		err = secWSKeyMalformedError
	} else {
		h := sha1.New()
		h.Write([]byte(key + guid)) // sha1(key + guid)
		fmt.Println(key)
		fmt.Printf("% x", h)
		secWSAccept = base64.StdEncoding.EncodeToString(h.Sum(nil))
	}
	return
}
