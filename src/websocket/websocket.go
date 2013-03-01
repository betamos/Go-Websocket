package websocket

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
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
	fin           bool
	opCode        byte
	mask          bool
	payloadLength int64
	maskingKey    []byte
}

func newFrameHeader(fin bool, opCode byte, payloadLength int64, maskingKey []byte) (fh *frameHeader, err error) {
	if _, ok := opCodeDescriptions[opCode]; !ok {
		// If an unknown opcode is received, the receiving endpoint MUST _Fail the
		// WebSocket Connection_.
		err = errMalformedFrameHeader
		return
	}
	controlFrame := opCode&opCodeControlFrame != 1
	if controlFrame && (!fin || payloadLength > 125) {
		// All control frames MUST have a payload length of 125 bytes or less and
		// MUST NOT be fragmented.
		err = errMalformedFrameHeader
		return
	}
	if payloadLength < 0 {
		err = errMalformedFrameHeader
		return
	}
	mask := maskingKey != nil
	if mask && len(maskingKey) != 4 {
		err = errMalformedFrameHeader
		return
	}
	fh = &frameHeader{
		fin:           fin,
		opCode:        opCode,
		mask:          mask,
		payloadLength: payloadLength,
		maskingKey:    maskingKey,
	}
	return
}

// Reads and parses the websocket frame header.
// The error is EOF only if no bytes were read. If an EOF happens after reading
// some but not all the bytes, parseFrameHeader returns ErrUnexpectedEOF. 
// If the frame header is malformed, the error is errMalformedFrameheader.
func parseFrameHeader(r io.Reader) (fh *frameHeader, err error) {
	// The first two bytes, containing most of the header data
	op := make([]byte, 2)
	if _, err = io.ReadFull(r, op); err != nil {
		return
	}
	if rsvMask&op[0] != 0 {
		// No RSV bits are allowed without extension
		err = errMalformedFrameHeader
		return
	}
	var (
		payloadLength = int64(op[1] & payloadLength7)
		mask          = op[1]&mask != 0
		maskingKey    []byte
	)

	// Read the extended payload length and update fh accordingly
	// TODO: DRY
	if payloadLength == 126 {
		var len16 uint16
		if binary.Read(r, binary.BigEndian, &len16) != nil {
			err = io.ErrUnexpectedEOF
			return
		}
		if payloadLength < 126 {
			// Minimum number of bytes not used
			err = errMalformedFrameHeader
			return
		}
		payloadLength = int64(len16)
	} else if payloadLength == 127 {
		if binary.Read(r, binary.BigEndian, &payloadLength) != nil {
			err = io.ErrUnexpectedEOF
			return
		}
		if payloadLength <= math.MaxUint16 {
			// Minimum number of bytes not used
			err = errMalformedFrameHeader
			return
		}
	}

	// If payload is masked, read masking key
	if mask {
		maskingKey = make([]byte, 4)
		if _, err = io.ReadFull(r, maskingKey); err != nil {
			err = io.ErrUnexpectedEOF
		}
	}
	fh, err = newFrameHeader(op[0]&fin != 0, op[0]&opCodeMask, payloadLength, maskingKey)
	return
}

func (fh *frameHeader) String() (s string) {
	operation, ok := opCodeDescriptions[fh.opCode]
	if !ok {
		operation = fmt.Sprintf("invalid operation [%X]", fh.opCode)
	}
	return fmt.Sprintf("Fin: %t, Op: %s, Mask: %t, PayloadLen: %v, MaskingKey: %X",
		fh.fin, operation, fh.mask, fh.payloadLength, fh.maskingKey)
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
		binary.BigEndian.PutUint64(extLen, uint64(fh.payloadLength))
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
}

func NewConn(conn net.Conn, rw *bufio.ReadWriter) (c *Conn) {
	in := make(chan io.Reader)
	c = &Conn{
		conn: conn,
		rw:   rw,
		in:   in,
		In:   in,
	}
	return
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
	closeFrame, err := newFrameHeader(true, opCodeConnectionClose, int64(2+len(reason)), nil)
	if err != nil {
		log.Fatal("Close frame payload too long")
	}
	c.rw.Write(closeFrame.Bytes())
	binary.Write(c.rw, binary.BigEndian, code)
	c.rw.WriteString(reason)
	c.rw.Flush()
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
	c.conn.Close()
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
