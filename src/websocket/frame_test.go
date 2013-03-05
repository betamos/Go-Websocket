package websocket

import (
	"bytes"
	"reflect"
	"testing"
)

func TestControlEmpty(t *testing.T) {
	if _, err := newFrameHeader(true, opCodePing, 0, nil); err != nil {
		t.Fail()
	}
}

func TestControlNormal(t *testing.T) {
	if _, err := newFrameHeader(true, opCodePing, 125, nil); err != nil {
		t.Fail()
	}
}

func TestControlTooBig(t *testing.T) {
	if _, err := newFrameHeader(true, opCodePing, 126, nil); err == nil {
		t.Fail()
	}
}

func TestControlContinuation(t *testing.T) {
	if _, err := newFrameHeader(false, opCodeConnectionClose, 126, nil); err == nil {
		t.Fail()
	}
}

func TestNegativePayloadLength(t *testing.T) {
	if _, err := newFrameHeader(true, opCodeText, -1, nil); err == nil {
		t.Fail()
	}
}

func TestParseTextFrame(t *testing.T) {
	buf := bytes.NewBuffer([]byte{
		0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f,
	})
	// A single-frame unmasked text message (contains "Hello")
	hello := bytes.NewBufferString("Hello")
	eqFh, _ := newFrameHeader(true, opCodeText, int64(hello.Len()), nil)
	f, err := nextFrame(buf)
	if err != nil {
		t.Error("nextFrame returns error")
		t.FailNow()
	}
	if f.header == nil {
		t.Error("No frame header returned")
		t.FailNow()
	}
	if !reflect.DeepEqual(*f.header, *eqFh) {
		t.Errorf("Frame headers not considered equal \n[   ref: %v] \n[actual: %v]", eqFh, f.header)
	}
	w := new(bytes.Buffer)
	_, err = f.readPayloadTo(w)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	if !reflect.DeepEqual(w.Bytes(), hello.Bytes()) {
		t.Errorf("Message mismatch %v %v", w.Bytes(), hello.Bytes())
	}
}

func TestParseMaskedTextFrame(t *testing.T) {
	buf := bytes.NewBuffer([]byte{
		0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58,
	})
	// A single-frame unmasked text message (contains "Hello")
	hello := bytes.NewBufferString("Hello")
	eqFh, _ := newFrameHeader(true, opCodeText, int64(hello.Len()), []byte{0x37, 0xfa, 0x21, 0x3d})
	f, err := nextFrame(buf)
	if err != nil {
		t.Error("nextFrame returns error")
		t.FailNow()
	}
	if f.header == nil {
		t.Error("No frame header returned")
		t.FailNow()
	}
	if !reflect.DeepEqual(*f.header, *eqFh) {
		t.Errorf("Frame headers not considered equal \n[   ref: %v] \n[actual: %v]", eqFh, f.header)
	}
	w := new(bytes.Buffer)
	_, err = f.readPayloadTo(w)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	if !reflect.DeepEqual(w.Bytes(), hello.Bytes()) {
		t.Errorf("Message mismatch %v %v", w.Bytes(), hello.Bytes())
	}
}
