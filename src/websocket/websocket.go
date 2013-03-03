package websocket

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
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
	fin                = byte(0x80)
	rsvMask            = byte(0x70)
	opCodeMask         = byte(0x0F)
	opCodeContinuation = byte(0x00)
	opCodeText         = byte(0x01)
	opCodeBinary       = byte(0x02)

	// Control frames are identified by opcodes where the most significant bit of
	// the opcode is 1.
	opCodeControlFrame    = byte(0x08) // MSB of opCode
	opCodeConnectionClose = byte(0x08)
	opCodePing            = byte(0x09)
	opCodePong            = byte(0x0A)
	mask                  = byte(0x80)
	payloadLength7        = byte(0x7F)
)

const (
	statusNormalClosure   = uint16(1000)
	statusGoingAway       = uint16(1001)
	statusProtocolError   = uint16(1002)
	statusUnsupportedData = uint16(1003)
)

var (
	errMalformedClientHandshake = errors.New("Malformed handshake request from client")
	errMalformedSecWSKey        = errors.New("Malformed Sec-WebSocket-Key")
)

var opCodeDescriptions = map[byte]string{
	opCodeContinuation:    "continuation frame",
	opCodeText:            "text frame",
	opCodeBinary:          "binary frame",
	opCodeConnectionClose: "connection close",
	opCodePing:            "ping",
	opCodePong:            "pong",
}

// A websocket handler, implements http.Handler
type Handler struct {
	Conns chan *Conn
}

func NewHandler() (h *Handler) {
	h = &Handler{
		Conns: make(chan *Conn),
	}
	return
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
	w.WriteHeader(status)
	hj, ok := w.(http.Hijacker)
	if !ok {
		log.Fatal("No HTTP hijacking")
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		log.Fatal(err)
	}
	rw.WriteString("\r\n")
	rw.Flush()
	client := NewConn(conn, rw)
	h.Conns <- client
	client.loop()
}

type Conn struct {
	conn        net.Conn
	clientClose bool // Has the client sent a close frame
	rw          *bufio.ReadWriter
	in          chan<- io.Reader
	In          <-chan io.Reader
	out         <-chan io.Writer
	Out         chan<- io.Writer
	send        chan *frame
}

func NewConn(conn net.Conn, rw *bufio.ReadWriter) (c *Conn) {
	in := make(chan io.Reader)
	out := make(chan io.Writer)
	send := make(chan *frame)
	c = &Conn{
		conn: conn,
		rw:   rw,
		in:   in,
		In:   in,
		out:  out,
		Out:  out,
		send: send,
	}
	buf := bytes.NewBufferString("hejsan\n")
	fh, _ := newFrameHeader(true, opCodeText, int64(buf.Len()), nil)
	go func() { send <- newFrame(fh, buf) }()
	go c.sendLoop()
	return
}

// Blocking send loop
// Send loop processes frames, meaning that fragmented
// messages can be sent
func (c *Conn) sendLoop() {
	var err error
	for frame, ok := <-c.send; ok; frame, ok = <-c.send {
		fmt.Println("FRAME: ", frame.header)
		_, err = c.rw.Write(frame.header.Bytes())
		if err != nil {
			break
		}
		if frame.header.payloadLength > 0 {
			_, err = io.CopyN(c.rw, frame.payload, frame.header.payloadLength) // TODO: Payload length?
			if err != nil {
				break
			}
			c.rw.Flush()
		}
	}
	c.conn.Close()
	fmt.Println("No more send messages")
}

func (c *Conn) loop() {
	code := statusNormalClosure
	reason := ""
	var (
		fh  *frameHeader
		err error
	)
NewMessages:
	for {
		if fh, err = parseFrameHeader(c.rw); err != nil {
			// TODO: Proper logging?
			log.Println("Could not parse frame header", c.conn.RemoteAddr(), err, "Closing websocket")
			code = statusProtocolError
			reason = err.Error()
			break NewMessages
		}
		fmt.Println(fh)
		switch fh.opCode {
		case opCodePing:
			// Mutex
			// c.rw.Write(pong)
		case opCodeBinary:
			fallthrough // Currently binary and text are recieved in the same way
		case opCodeText:
			r, w := io.Pipe()
			bw := bufio.NewWriter(w)
			c.in <- r
			for i := int64(0); i < fh.payloadLength; i++ {
				b, err := c.rw.ReadByte()
				if err != nil {
					w.CloseWithError(io.ErrUnexpectedEOF)
					return
				}
				bw.WriteByte(fh.maskingKey[i%4] ^ b)
			}
			bw.Flush()
			w.Close() // Close the pipe writer with an EOF
		case opCodeConnectionClose:
			c.clientClose = true
			break NewMessages
		default:
			fmt.Printf("Unhandled operation %X\n", fh.opCode)
		}
	}
	c.close(code, reason)
}

// Initiate closing handshake and close underlying TCP connection.
// Discard all new incoming messages and terminate current outgoing messages.
func (c *Conn) close(code uint16, reason string) {
	close(c.in) // Close the channel for new messages
	closeFrame, err := newCloseFrame(code, reason)
	if err != nil {
		log.Fatal("Close frame payload too long")
	}
	c.send <- closeFrame
	close(c.send)
	// Client has not yet sent the closing frame
	for !c.clientClose {
		if fh, err := parseFrameHeader(c.rw); err == nil {
			if fh.opCode == opCodeConnectionClose {
				c.clientClose = true
			}
			// When in closing state, discard the payload
			// TODO: Read the code and reason for close?
			io.CopyN(ioutil.Discard, c.rw, int64(fh.payloadLength))
		} else {
			log.Println("The client ", c.conn.RemoteAddr(), " did NOT properly complete the WebSocket closing handshake")
			break
		}
	}
}

// Send a message to the client
// TODO: Fragmentation, this requires a lot of memory for large messages
func (c *Conn) Send(p []byte) (n int, err error) {
	fh := &frameHeader{
		fin:           true,
		opCode:        opCodeText,
		payloadLength: int64(len(p)),
	}
	_, err = c.rw.Write(fh.Bytes())
	if err != nil {
		return
	}
	_, err = c.rw.Write(p)
	return
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
