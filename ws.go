package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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
	opCodeContinuation    = byte(0x00)
	opCodeText            = byte(0x01)
	opCodeBinary          = byte(0x02)
	opCodeConnectionClose = byte(0x08)
	opCodePing            = byte(0x09)
	opCodePong            = byte(0x0A)
	mask                  = byte(0x80)
	payloadLength7        = byte(0x7F)
)

var (
	errMalformedClientHandshake = errors.New("Malformed handshake request from client")
	errMalformedSecWSKey        = errors.New("Malformed Sec-WebSocket-Key")
	errMalformedFrameHeader     = errors.New("Malformed frame header from client")
)

var opCodeDescriptions = map[byte]string{
	opCodeContinuation:    "continuation frame",
	opCodeText:            "text frame",
	opCodeBinary:          "binary frame",
	opCodeConnectionClose: "connection close",
	opCodePing:            "ping",
	opCodePong:            "pong",
}

type frameHeader struct {
	fin, rsv1, rsv2, rsv3 bool
	opCode                byte
	mask                  bool
	payloadLength         uint64
	maskingKey            []byte
}

func (h *frameHeader) String() (s string) {
	operation, ok := opCodeDescriptions[h.opCode]
	if !ok {
		operation = fmt.Sprintf("invalid operation [%X]", h.opCode)
	}
	return fmt.Sprintf("Fin: %t, (Rsv: %t %t %t), Op: %s, Mask: %t, PayloadLen: %v, MaskingKey: %X",
		h.fin, h.rsv1, h.rsv2, h.rsv3, operation, h.mask, h.payloadLength, h.maskingKey)
}

func main() {
	fmt.Println("Web socketaaa")
	http.Handle("/", http.FileServer(http.Dir("web")))
	http.HandleFunc("/myconn", func(w http.ResponseWriter, r *http.Request) {
		//fmt.Println(r)
		var status int
		secWSAccept, err := wsClientHandshake(r)
		if err != nil {
			fmt.Println(err)
			w.Header().Set("Sec-WebSocket-Version", strconv.Itoa(secWSVersion))
			status = http.StatusBadRequest
		} else {
			// TODO: Map or list instead?
			w.Header().Set("Upgrade", "websocket")
			w.Header().Set("Connection", "Upgrade")
			w.Header().Set("Sec-WebSocket-Accept", secWSAccept)
			status = http.StatusSwitchingProtocols
		}
		fmt.Printf("Close: %v\n", r.Close)
		w.WriteHeader(status)
		w.Write([]byte{0x4e})
		hj, ok := w.(http.Hijacker)
		if !ok {
			fmt.Println("No hijack")
		}
		fmt.Println("header written")
		conn, rw, err := hj.Hijack()
		fmt.Println(conn, rw)
		go func() {
			// Read the frameHeader
			for i := 0; i < 2; i++ {
				header, err := parseFrameHeader(bufio.NewReader(rw))
				// TODO: Somehow return errMalformedFrameHeader
				if err != nil {
					fmt.Println("err", err)
				} else {
					fmt.Println("header", header)
				}
			}
			return
		}()
		ping := []byte{
			//0x81, // fin, rsv[0..2] = 0, opcode = text frame
			//0x02,
			//0x41,
			//0x42,
			//0x81,
			0x89,
			0x00,
		}
		rw.WriteString("\r\n")
		fmt.Println("Flushed")
		rw.Write(ping)
		ab := []byte{
			0x81, // fin, rsv[0..2] = 0, opcode = text frame
			0x02,
			0x41,
			0x42,
		}
		bin := []byte{
			0x82, // fin, rsv[0..2] = 0, opcode = text frame
			0x02,
			0x10,
			0xff,
		}
		rw.Write(ab)
		rw.Write(bin)
		rw.Flush()
	})
	log.Fatal(http.ListenAndServe("localhost:8080", nil))
}

// Parse the websocket frame header
// Generates an error if malformed or the stream is interrupted
func parseFrameHeader(r *bufio.Reader) (header *frameHeader, err error) {
	header = &frameHeader{}
	if c, err := r.ReadByte(); err != nil {
		return nil, err
	} else {
		header.fin = c&fin != 0
		header.rsv1 = c&rsv1 != 0
		header.rsv2 = c&rsv2 != 0
		header.rsv3 = c&rsv3 != 0
		header.opCode = c & opCode
	}
	// TODO: Check opcode?
	if c, err := r.ReadByte(); err != nil {
		return nil, err
	} else {
		header.mask = c&mask != 0
		header.payloadLength = uint64(c & payloadLength7)
	}
	if header.payloadLength == 126 {
		buf := make([]byte, 4)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		header.payloadLength = uint64(binary.BigEndian.Uint16(buf))
	} else if header.payloadLength == 127 {
		buf := make([]byte, 8)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		header.payloadLength = binary.BigEndian.Uint64(buf)
	}
	if header.mask {
		header.maskingKey = make([]byte, 4)
		if _, err := io.ReadFull(r, header.maskingKey); err != nil {
			return nil, err
		}
	}
	return header, nil
}

func wsClientHandshake(r *http.Request) (secWSAccept string, err error) {

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
		err = errMalformedSecWSKey
	} else {
		h := sha1.New()
		h.Write([]byte(key + guid)) // sha1(key + guid)
		secWSAccept = base64.StdEncoding.EncodeToString(h.Sum(nil))
	}
	return
}
