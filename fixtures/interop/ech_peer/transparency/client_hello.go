package main

import (
	"encoding/binary"
	"errors"
	"net"
	"sync"
)

// Observe only the bounded first ClientHello, before Go TLS consumes the exact
// same bytes. This distinguishes GREASE from absence without decrypting TLS or
// changing its transcript. Completed observations release their byte buffers.
type clientHelloObserver struct {
	mu       sync.Mutex
	pending  []byte
	hello    []byte
	finished bool
	observed bool
	present  bool
	err      string
}

func (o *clientHelloObserver) finish(observed, present bool, err string) {
	o.finished, o.observed, o.present, o.err = true, observed, present, err
	o.pending, o.hello = nil, nil
}

func (o *clientHelloObserver) feed(data []byte) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.finished {
		return
	}
	if len(o.pending)+len(data) > 96*1024 {
		o.finish(false, false, "record-buffer-limit")
		return
	}
	o.pending = append(o.pending, data...)
	for len(o.pending) >= 5 {
		if o.pending[0] != 22 {
			o.finish(false, false, "first-message-not-handshake")
			return
		}
		length := int(binary.BigEndian.Uint16(o.pending[3:5]))
		if length == 0 || length > 18432 {
			o.finish(false, false, "record-length")
			return
		}
		if len(o.pending) < length+5 {
			return
		}
		if len(o.hello)+length > 64*1024+4 {
			o.finish(false, false, "client-hello-limit")
			return
		}
		o.hello = append(o.hello, o.pending[5:5+length]...)
		o.pending = o.pending[5+length:]
		if len(o.hello) < 4 {
			continue
		}
		bodyLength := int(o.hello[1])<<16 | int(o.hello[2])<<8 | int(o.hello[3])
		if o.hello[0] != 1 || bodyLength > 64*1024 {
			o.finish(false, false, "client-hello-header")
			return
		}
		if len(o.hello) < 4+bodyLength {
			continue
		}
		present, err := clientHelloHasECH(o.hello[4 : 4+bodyLength])
		if err != nil {
			o.finish(false, false, "client-hello-extensions")
		} else {
			o.finish(true, present, "")
		}
		return
	}
}

func (o *clientHelloObserver) result() (bool, bool, string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.observed, o.present, o.err
}

func clientHelloHasECH(body []byte) (bool, error) {
	invalid := errors.New("invalid ClientHello")
	if len(body) < 35 {
		return false, invalid
	}
	// Legacy version, random, session ID, cipher suites, compression methods.
	offset := 34
	for _, width := range []int{1, 2, 1} {
		if len(body)-offset < width {
			return false, invalid
		}
		length := int(body[offset])
		if width == 2 {
			length = int(binary.BigEndian.Uint16(body[offset : offset+2]))
		}
		offset += width
		if len(body)-offset < length {
			return false, invalid
		}
		offset += length
	}
	if offset == len(body) {
		return false, nil
	}
	if len(body)-offset < 2 {
		return false, invalid
	}
	length := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2
	if len(body)-offset != length {
		return false, invalid
	}
	present := false
	for offset < len(body) {
		if len(body)-offset < 4 {
			return false, invalid
		}
		kind := binary.BigEndian.Uint16(body[offset : offset+2])
		size := int(binary.BigEndian.Uint16(body[offset+2 : offset+4]))
		offset += 4
		if len(body)-offset < size {
			return false, invalid
		}
		present = present || kind == 0xfe0d
		offset += size
	}
	return present, nil
}

type helloContextKey struct{}

type observedConn struct {
	net.Conn
	observer *clientHelloObserver
}

func (c *observedConn) Read(data []byte) (int, error) {
	n, err := c.Conn.Read(data)
	if n > 0 {
		c.observer.feed(data[:n])
	}
	return n, err
}

type observedListener struct{ net.Listener }

func (l observedListener) Accept() (net.Conn, error) {
	connection, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &observedConn{Conn: connection, observer: &clientHelloObserver{}}, nil
}
