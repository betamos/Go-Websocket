package websocket

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

var (
	errMalformedFrameHeader = errors.New("Malformed frame header")
)

type frameHeader struct {
	fin           bool
	opCode        byte
	mask          bool
	payloadLength int64
	maskingKey    []byte
}

// Create and validate new frame header.
// If maskingKey is NOT nil, fh.mask will be true.
// Validates and returns errMalformedFrameHeader if any rules are broken.
func newFrameHeader(fin bool, opCode byte, payloadLength int64, maskingKey []byte) (fh *frameHeader, err error) {
	if _, ok := opCodeDescriptions[opCode]; !ok {
		// If an unknown opcode is received, the receiving endpoint MUST _Fail the
		// WebSocket Connection_.
		err = errMalformedFrameHeader
		return
	}
	controlFrame := opCode&opCodeControlFrame != 0
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

// True if the frameHeader is a control frame, (ping, pong or connection close)
func (fh *frameHeader) controlFrame() bool {
	return fh.opCode&opCodeControlFrame != 0
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
