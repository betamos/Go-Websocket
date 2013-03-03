package websocket

import (
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

var (
	pingFrameHeader, _ = newFrameHeader(true, opCodePing, 0, nil)
	pongFrameHeader, _ = newFrameHeader(true, opCodePong, 0, nil)
	pingFrame          = newFrame(pingFrameHeader, nil)
	pongFrame          = newFrame(pongFrameHeader, nil)
)
