package websocket

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
)

type frame struct {
	header  *frameHeader
	payload io.Reader
}

func newFrame(header *frameHeader, payload io.Reader) (f *frame) {
	f = &frame{
		header:  header,
		payload: payload,
	}
	return
}

// Wrapper around parseFrameHeader, returns the same error
// Doesn't read anything from payload, just the header
func nextFrame(r io.Reader) (f *frame, err error) {
	var fh *frameHeader
	fh, err = parseFrameHeader(r)
	if err != nil {
		return
	}
	f = newFrame(fh, r)
	return
}

// Payload length for this frame
func (f *frame) Len() int64 {
	return f.header.payloadLength
}

// Payload length for this frame
func (f *frame) Op() (opCode byte) {
	opCode = f.header.opCode
	return
}

// TODO: Reason must be valid UTF-8
func newCloseFrame(e *errConnection) (f *frame, err error) {
	reasonBytes := []byte(e.reason)
	payloadLength := int64(2 + len(reasonBytes))
	var fh *frameHeader
	fh, err = newFrameHeader(true, opCodeConnectionClose, payloadLength, nil)
	if err != nil {
		return
	}
	buf := bytes.NewBuffer(make([]byte, 0, payloadLength))
	binary.Write(buf, binary.BigEndian, e.code)
	buf.Write(reasonBytes)
	f = &frame{
		header:  fh,
		payload: buf,
	}
	return
}

// Read the payload data from frame.payload into w.
// Will mask if f.header.mask is set
// Err will be io.
func (f *frame) readPayloadTo(w io.Writer) (n int64, err error) {
	if f.Len() == 0 { // No payload
		return
	}
	br := bufio.NewReader(f.payload)
	bw := bufio.NewWriter(w)
	var c byte
	if f.header.mask {
		for n = int64(0); n < f.header.payloadLength; n++ {
			c, err = br.ReadByte()
			if err != nil {
				err = io.ErrUnexpectedEOF
				return
			}
			err = bw.WriteByte(f.header.maskingKey[n%4] ^ c)
			if err != nil {
				err = io.ErrShortWrite
				return
			}
		}
	} else {
		n, err = io.CopyN(bw, br, f.header.payloadLength)
		if n == f.header.payloadLength && err == io.EOF {
			// This is no error
			err = nil
		}
	}
	err = bw.Flush()
	return
}
