package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
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

func (fh *frameHeader) String() (s string) {
	operation, ok := opCodeDescriptions[fh.opCode]
	if !ok {
		operation = fmt.Sprintf("invalid operation [%X]", fh.opCode)
	}
	return fmt.Sprintf("Fin: %t, (Rsv: %t %t %t), Op: %s, Mask: %t, PayloadLen: %v, MaskingKey: %X",
		fh.fin, fh.rsv1, fh.rsv2, fh.rsv3, operation, fh.mask, fh.payloadLength, fh.maskingKey)
}

// Converts frame header to binary data ready to be sent.
// Warning, this method is optimized for server sending, it DOES ignore certain
// aspects of the header such as rsv bits and presumes there is no masking,
// according to the specification. Does not validate op code.
func (fh *frameHeader) Bytes() []byte {
	// Use buffer to prevent errors
	buffer := bytes.NewBuffer(make([]byte, 0, 10))
	if fh.fin {
		buffer.WriteByte(fin | fh.opCode)
	} else {
		buffer.WriteByte(fh.opCode)
	}
	var (
		baseLen byte // First length byte
		lenLen  int  // Length of the extended payload length (bytes)
	)
	extLen := make([]byte, 8)
	if fh.payloadLength > math.MaxUint16 {
		baseLen = 127
		lenLen = 8
		binary.BigEndian.PutUint64(extLen, fh.payloadLength)
	} else if fh.payloadLength > 125 {
		baseLen = 126
		lenLen = 2
		binary.BigEndian.PutUint16(extLen, uint16(fh.payloadLength))
	} else {
		baseLen = byte(fh.payloadLength)
		lenLen = 0
	}
	extLen = extLen[:lenLen]
	buffer.WriteByte(baseLen)
	buffer.Write(extLen)
	return buffer.Bytes()
}

type Client struct {
	rw *bufio.ReadWriter
	In chan io.Reader // Bytes that should be read by recieve
}

func NewClient(rw *bufio.ReadWriter) (c *Client) {
	c = &Client{
		rw: rw,
		In: make(chan io.Reader),
	}
	return
}

func (c *Client) loop() {
	defer close(c.In)
	for {
		fh := parseFrameHeader(c.rw)
		fmt.Println(fh)
		if fh == nil {
			return
		}
		switch fh.opCode {
		case opCodePing:
			// Mutex
			// c.rw.Write(pong)
		case opCodeBinary:
			fallthrough // Currently binary and text are recieved in the same way
		case opCodeText:
			r, w := io.Pipe()
			c.In <- r
			for i := uint64(0); i < fh.payloadLength; i++ {
				b, err := c.rw.ReadByte()
				if err != nil {
					w.CloseWithError(io.ErrUnexpectedEOF)
					return
				}
				w.Write([]byte{fh.maskingKey[i%4] ^ b})
			}
			w.Close() // Close the pipe writer with an EOF
		case opCodeConnectionClose:
			return
		default:
			fmt.Printf("Unhandled operation %X\n", fh.opCode)
		}
	}
}

// Send a message to the client
// TODO: Fragmentation, this requires a lot of memory for large messages
func (c *Client) Send(p []byte) (n int, err error) {
	fh := &frameHeader{
		fin:           true,
		opCode:        opCodeText,
		payloadLength: uint64(len(p)),
	}
	_, err = c.rw.Write(fh.Bytes())
	if err != nil {
		return
	}
	_, err = c.rw.Write(p)
	return
}

func main() {
	// TODO: Attach to future handler
	clients := make(chan *Client)
	go func() {
		for c, ok := <-clients; ok; c, ok = <-clients {
			//go func() {
			// Client processing
			fmt.Println("New client", c)
			for r, ok := <-c.In; ok; r, ok = <-c.In {
				// Print messages
				io.Copy(os.Stdout, r)
			}
			fmt.Println("No more messages")
			//}()
		}
		fmt.Println("No more clients")
	}()

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
		rw.WriteString("\r\n")
		rw.Flush()
		client := NewClient(rw)
		clients <- client
		client.loop()
	})
	log.Fatal(http.ListenAndServe("localhost:8080", nil))
}

// Parse the websocket frame header
// Generates an error if malformed or the stream is interrupted
func parseFrameHeader(rw *bufio.ReadWriter) (header *frameHeader) {
	header = &frameHeader{}
	if c, err := rw.ReadByte(); err != nil {
		return nil
	} else {
		header.fin = c&fin != 0
		header.rsv1 = c&rsv1 != 0
		header.rsv2 = c&rsv2 != 0
		header.rsv3 = c&rsv3 != 0
		header.opCode = c & opCode
	}
	// TODO: Check opcode?
	if c, err := rw.ReadByte(); err != nil {
		return nil
	} else {
		header.mask = c&mask != 0
		header.payloadLength = uint64(c & payloadLength7)
	}
	if header.payloadLength == 126 {
		buf := make([]byte, 4)
		if _, err := io.ReadFull(rw, buf); err != nil {
			return nil
		}
		header.payloadLength = uint64(binary.BigEndian.Uint16(buf))
	} else if header.payloadLength == 127 {
		buf := make([]byte, 8)
		if _, err := io.ReadFull(rw, buf); err != nil {
			return nil
		}
		header.payloadLength = binary.BigEndian.Uint64(buf)
	}
	if header.mask {
		header.maskingKey = make([]byte, 4)
		if _, err := io.ReadFull(rw, header.maskingKey); err != nil {
			return nil
		}
	}
	return header
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
