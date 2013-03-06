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
	"time"
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

var Log = log.New(ioutil.Discard, "", log.LstdFlags)

// A websocket handler, implements http.Handler
type Handler struct {
	Conns chan *Conn
}

func NewHandler() (h *Handler) {
	h = &Handler{
		Conns: make(chan *Conn, 0x10),
	}
	return
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var status int
	secWSAccept, err := wsClientHandshake(r)
	if err != nil {
		Log.Println(err)
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
	c := newConn(conn)
	h.Conns <- c
	c.start()
}

// Connection states for websocket connections
const (
	CONNECTING = iota
	OPEN
	CLOSING
	CLOSED
)

// A connection error
type errConnection struct {
	code   uint16
	reason string
}

func (e *errConnection) Error() string {
	return fmt.Sprintf("Error %v: %v", e.code, e.reason)
}

func newErrConnection(code uint16, reason string) (e *errConnection) {
	e = &errConnection{
		code:   code,
		reason: reason,
	}
	return
}

var (
	errNormalClosure = newErrConnection(statusNormalClosure, "")
)

type Conn struct {
	conn                     net.Conn
	clientClose              bool // Has the client sent a close frame
	expectingContFrame       bool // Expecting a continuation frame, if fin wasn't set
	rw                       *bufio.ReadWriter
	in                       chan<- io.Reader
	In                       <-chan io.Reader
	out                      <-chan io.Reader
	Out                      chan<- io.Reader
	send                     chan *frame
	currWriter               *io.PipeWriter // Current message writer (for fragmented messages)
	State                    int            // The connection state
	closeSent, closeRecieved bool           // Log that a close frame has been sent and recieved
	Cleanly                  bool           // Was the connection closed cleanly?
	server                   bool           // True if connection is server, false if client
}

func newConn(conn net.Conn) (c *Conn) {
	in := make(chan io.Reader, 0x10)
	out := make(chan io.Reader, 0x10)
	send := make(chan *frame, 0x10) // Message buffer
	c = &Conn{
		conn:   conn,
		rw:     bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn)),
		in:     in,
		In:     in,
		out:    out,
		Out:    out,
		send:   send,
		State:  OPEN,
		server: true,
	}
	return
}

func (c *Conn) start() {
	Log.Println("Conn started")
	go c.sendLoop()
	go func() {
		err := c.router()
		if err != nil {
			Log.Print(err)
			c.closing()
			c.destroy(false)
		}
	}()
	go c.sendMessageLoop()
}

// Retrieves messages from c.Out, fragments them and sends them away.
func (c *Conn) sendMessageLoop() {
	// Read all
	var (
		n   int64
		max int64 = 128
		fh  *frameHeader
		f   *frame
		fin bool
		op  byte
	)
	for r, ok := <-c.out; ok && c.State == OPEN; r, ok = <-c.out {
		var err error
		br := bufio.NewReader(r)
		op = opCodeText // First frame, always text
		for err == nil {
			buf := bytes.NewBuffer(make([]byte, 0, max))
			n, err = io.CopyN(buf, br, max)
			fin = err == io.EOF // Last frame
			fh, _ = newFrameHeader(fin, op, n, nil)
			f = newFrame(fh, buf)
			c.send <- f
			op = opCodeContinuation
		}
	}
}

// Blocking send loop
// Send loop processes frames, meaning that fragmented
// messages can be sent
func (c *Conn) sendLoop() {
	var err error
	for f, ok := <-c.send; ok; f, ok = <-c.send {
		_, err = c.rw.Write(f.header.Bytes())
		if err != nil {
			break
		}
		if f.header.payloadLength > 0 {
			_, err = io.CopyN(c.rw, f.payload, f.header.payloadLength) // TODO: Payload length?
			if err != nil {
				break
			}
			c.rw.Flush()
		}
	}
	c.destroy(true)
}

// Randomize a new masking key if client, or no masing if server
// TODO
func (c *Conn) mask() (maskingKey []byte) {
	return nil
}

// Read and respond to a ping frame
func (c *Conn) processPing(f *frame) (err error) {
	var payloadCopy bytes.Buffer
	_, err = f.readPayloadTo(&payloadCopy)
	if err != nil {
		return
	}
	pongFrameHeader, _ := newFrameHeader(true, opCodePong, f.Len(), c.mask())
	pongFrame := newFrame(pongFrameHeader, &payloadCopy)
	c.send <- pongFrame
	return
}

// Read and respond to a pong frame
func (c *Conn) processPong(f *frame) (err error) {
	_, err = f.readPayloadTo(ioutil.Discard)
	return
}

// Process a text frame
func (c *Conn) processText(f *frame) (err error) {
	// TODO: Incoming data MUST always be validated by both clients and servers.
	if c.expectingContFrame {
		err = newErrConnection(statusProtocolError, "Received unexpected data frame (expecting continuation frame)")
		return
	}
	var r *io.PipeReader
	r, w := io.Pipe()
	c.in <- r
	_, err = f.readPayloadTo(w)
	if err == io.ErrUnexpectedEOF {
		w.CloseWithError(io.ErrUnexpectedEOF)
		return
	} else {
		if f.header.fin {
			w.Close() // Close the pipe writer with an EOF
		} else {
			c.currWriter = w
		}
	}
	return
}

// Read continuation frame into current write stream
func (c *Conn) processContinuation(f *frame) (err error) {
	if c.currWriter == nil {
		err = newErrConnection(statusProtocolError, "Recieved unexpected continuation frame")
		return
	}
	w := c.currWriter
	_, err = f.readPayloadTo(w)
	if err == io.ErrUnexpectedEOF {
		w.CloseWithError(io.ErrUnexpectedEOF)
		err = newErrConnection(statusProtocolError, "The other end-point closed the TCP connection")
		return
	} else {
		if f.header.fin {
			w.Close() // Close the pipe writer with an EOF
			c.currWriter = nil
			w = nil
		}
	}
	return
}

// When called, closeReceived = true, c.State = OPEN | CLOSING
func (c *Conn) processConnectionClose(f *frame) (err error) {
	c.State = CLOSING
	_, err = f.readPayloadTo(ioutil.Discard) // TODO
	if c.closeSent {
		// TODO: Can err affect internal logging?
		c.destroy(true) // All done, both sent and recieved
	} else {
		if err != nil {
			c.sendClose(newErrConnection(statusProtocolError, "Connection closed before close frame was sent"))
		} else {
			c.sendClose(errNormalClosure) // TODO: Mirror
		}
	}
	return
}

// Close user communication channels
func (c *Conn) closing() {
	c.State = CLOSING
	close(c.in)
	if c.currWriter != nil {
		c.currWriter.CloseWithError(io.ErrUnexpectedEOF)
		c.currWriter = nil
	}
}

// Initiate closing handshake and close underlying TCP connection.
// Discard all new incoming messages and terminate current outgoing messages.
func (c *Conn) sendClose(e *errConnection) {
	if c.closeSent {
		return
	}
	c.closing()
	closeFrame, _ := newCloseFrame(e)
	c.send <- closeFrame
	close(c.send)
	c.closeSent = true
}

// Close TCP connection and set clean flag
// Destroy does nothing if closing handshake is not complete, unless
// clean is false, in which case it destroys the connection anyway
// Can thus be called multiple times
func (c *Conn) destroy(clean bool) {
	if (c.closeRecieved && c.closeSent) || !clean {
		c.State = CLOSED
		c.Cleanly = clean
		if c.server || !clean {
			c.conn.Close()
		} else {
			c.conn.SetDeadline(time.Now().Add(time.Second * 5))
		}
		Log.Println("Conn stopped")
	}
}

// Blocking router method for incoming messages
func (c *Conn) router() (err error) {
	var f *frame
	for !c.closeRecieved {
		f, err = nextFrame(c.rw)
		// In the end of this loop, the payload must have been read
		if err != nil {
			return
		}

		if c.closeSent && f.Op() != opCodeConnectionClose {
			// Waiting for other end sending close frame
			// Ignore all frames except closing frames
			if _, err = f.readPayloadTo(ioutil.Discard); err != nil {
				return
			} else {
				continue
			}
		}

		switch f.Op() {
		case opCodePing:
			err = c.processPing(f)
		case opCodePong:
			err = c.processPong(f)
		case opCodeConnectionClose:
			c.closeRecieved = true
			err = c.processConnectionClose(f)
		case opCodeBinary:
			fallthrough // Currently binary and text are recieved in the same way
		case opCodeText:
			err = c.processText(f)
		case opCodeContinuation:
			err = c.processContinuation(f)
		}

		if err != nil {
			return
		}
	}
	return
}

// Close the websocket connection in a normal way
func (c *Conn) Close() {
	c.sendClose(errNormalClosure)
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
