// Pretend to be a client, and test that the server behaves correctly

package websocket

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"reflect"
	"testing"
	"time"
)

func setupServerAndHandshake(t *testing.T) (h *Handler, client net.Conn) {
	h = NewHandler()
	http.Handle("/myconn", h)
	go http.ListenAndServe(":8080", nil)
	var (
		req *http.Request
		err error
	)
	req, err = http.NewRequest("GET", "/myconn", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Origin", "http://localhost")
	req.Header.Set("Sec-WebSocket-Version", "13")
	client, err = net.Dial("tcp", "localhost:8080")
	if err != nil {
		t.Error("Couldn't open TCP connection")
		t.FailNow()
	}
	err = req.Write(client)
	if err != nil {
		t.Error("Could not write request")
		t.FailNow()
	}
	_, err = io.CopyN(ioutil.Discard, client, 194) // Fixed handshake length
	if err != nil {
		t.Error("Could not discard server handshake")
		t.FailNow()
	}
	return
}

// Check that the server closes the underlying TCP connection after client requests it.
func TestDirectClose(t *testing.T) {
	var (
		sending  = []byte{0x88, 0x80, 0x05, 0x06, 0x07, 0x08} // Request connection close
		expected = []byte{0x88, 0x02, 0x03, 0xE8}             // Connection close accepted and is clear
	)
	_, client := setupServerAndHandshake(t)
	_, err := io.Copy(client, bytes.NewBuffer(sending))
	if err != nil {
		t.Error("Couldn't write closing frame")
	}
	var buf bytes.Buffer
	_, err = io.CopyN(&buf, client, int64(len(expected)))
	if err != nil {
		t.Errorf("Short read: %v", err)
	}
	if !reflect.DeepEqual(buf.Bytes(), expected) {
		t.Errorf("Didn't recieve proper closing frame: %X", buf.Bytes())
	}
	// TODO: Make sure TCP connection was closed by server
	client.SetDeadline(time.Now().Add(time.Second))
	var n int64
	n, err = io.Copy(ioutil.Discard, client)
	fmt.Printf("%v copied\n", n)
	if n != 0 {
		t.Errorf("Recieved %v excess bytes", n)
	}
	if err != nil {
		t.Errorf("Server didn't close the TCP connection after closing frame (%v)", err)
	}
}
