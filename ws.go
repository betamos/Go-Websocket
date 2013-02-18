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
	"strconv"
	"strings"
)

const (
	guid           = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	secWSKeyLength = 16
	secWSVersion   = 13
	minProtoMajor  = 1
	minProtoMinor  = 1
)

// Bitmasks for protocol
const (
	fin                   = byte(0x80)
	rsv1                  = byte(0x40)
	rsv2                  = byte(0x20)
	rsv3                  = byte(0x10)
	opCode                = byte(0x0F)
	opCodeContiuation     = byte(0x00)
	opCodeText            = byte(0x01)
	opCodeBinary          = byte(0x02)
	opCodeConnectionClose = byte(0x08)
	opCodePing            = byte(0x09)
	opCodePong            = byte(0x0A)
	mask                  = byte(0x80)
	payloadLength7        = byte(0x7F)
)

type frameHeader struct {
	fin, rsv1, rsv2, rsv3 bool
	opCode                byte
	mask                  bool
	payloadLength         uint64
	maskingKey            []byte
}

var (
	errMalformedClientHandshake = errors.New("Malformed handshake request from client")
	errSecWSKeyMalformed        = errors.New("Malformed Sec-WebSocket-Key")
)

func main() {
	fmt.Println("Web socketaaa")
	http.Handle("/", http.FileServer(http.Dir("web")))
	http.HandleFunc("/myconn", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println(r)
		var status int
		secWSAccept, err := wsClientHandshake(w, r)
		if err != nil {
			fmt.Println(err)
			w.Header().Set("Sec-WebSocket-Version", secWSVersion)
			status = http.StatusBadRequest
		} else {
			// TODO: Map or list instead?
			w.Header().Set("Upgrade", "websocket")
			w.Header().Set("Connection", "Upgrade")
			w.Header().Set("Sec-WebSocket-Accept", secWSAccept)
			status = http.StatusSwitchingProtocols
		}
		w.WriteHeader(status)
	})
	log.Fatal(http.ListenAndServe("localhost:8080", nil))
}

func wsClientHandshake(w http.ResponseWriter, r *http.Request) (secWSAccept string, err error) {

	// Check HTTP version
	if !r.ProtoAtLeast(minProtoMajor, minProtoMinor) {
		err = errMalformedClientHandshake
		return
	}

	// Check HTTP header identifier for WebSocket
	if !(strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.EqualFold(r.Header.Get("Connection"), "Upgrade")) {
		err = errMalformedClientHandshake
		return
	}

	// Check WebSocket version
	if clientSecWSVersion, errFormat :=
		// TODO: Header.Get() just returns the first value, could be multiple
		strconv.Atoi(r.Header.Get("Sec-WebSocket-Version")); !(errFormat == nil && clientSecWSVersion == secWSVersion) {
		fmt.Println("hej")
		fmt.Println(clientSecWSVersion)
		err = errMalformedClientHandshake
		return
	}

	// Check Sec-WebSocket-Key
	secWSKey := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key"))
	return validateSecWebSocketKey(secWSKey)
}

// Validate and return the Sec-WebSocket-Accept calculated by the
// Sec-WebSocket-Key value.
func validateSecWebSocketKey(key string) (secWSAccept string, err error) {
	if decodedKey, _ := base64.StdEncoding.DecodeString(key); err != nil || len(decodedKey) != secWSKeyLength {
		err = errSecWSKeyMalformed
	} else {
		h := sha1.New()
		h.Write([]byte(key + guid)) // sha1(key + guid)
		fmt.Println(key)
		fmt.Printf("% x", h)
		secWSAccept = base64.StdEncoding.EncodeToString(h.Sum(nil))
	}
	return
}
