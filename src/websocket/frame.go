package websocket

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
)

var (
	pingFrameHeader, _ = newFrameHeader(true, opCodePing, 0, nil)
	pongFrameHeader, _ = newFrameHeader(true, opCodePong, 0, nil)
	pingFrame          = newFrame(pingFrameHeader, nil)
	pongFrame          = newFrame(pongFrameHeader, nil)
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

func newCloseFrame(code uint16, reason string) (f *frame, err error) {
	reasonBytes := []byte(reason)
	payloadLength := int64(2 + len(reasonBytes))
	fh, err := newFrameHeader(true, opCodeConnectionClose, payloadLength, nil)
	if err != nil {
		return
	}
	buf := bytes.NewBuffer(make([]byte, 0, payloadLength))
	binary.Write(buf, binary.BigEndian, code)
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
