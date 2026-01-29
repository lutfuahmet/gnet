// Copyright (c) 2019 The Gnet Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package gnet

import (
	"crypto/tls"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/panjf2000/gnet/v2/pkg/buffer/elastic"
)

// tlsNonBlockingState manages non-blocking TLS I/O for a connection.
// It wraps a tls.Conn with in-memory buffers to enable non-blocking operations.
type tlsNonBlockingState struct {
	tlsConn *tls.Conn   // the underlying TLS connection
	bufConn *bufferConn // buffer-backed net.Conn for tls.Conn

	// decryptedIn holds decrypted plaintext data ready for the application.
	// This is populated when we successfully decrypt TLS records.
	decryptedIn elastic.RingBuffer
}

// newTLSNonBlockingState creates a new non-blocking TLS state from an established tls.Conn.
// The tls.Conn should have already completed its handshake.
func newTLSNonBlockingState(tlsConn *tls.Conn, localAddr, remoteAddr net.Addr) *tlsNonBlockingState {
	bufConn := newBufferConn(localAddr, remoteAddr)

	// Create a new tls.Conn wrapper around our buffer-based net.Conn
	// We need to extract the connection state and create a wrapper
	state := &tlsNonBlockingState{
		tlsConn: tlsConn,
		bufConn: bufConn,
	}

	return state
}

// release cleans up the TLS non-blocking state resources.
func (s *tlsNonBlockingState) release() {
	if s.tlsConn != nil {
		_ = s.tlsConn.Close()
		s.tlsConn = nil
	}
	s.decryptedIn.Done()
	if s.bufConn != nil {
		s.bufConn.close()
		s.bufConn = nil
	}
}

// bufferConn implements net.Conn using in-memory buffers.
// This allows tls.Conn to read/write without touching the actual socket.
type bufferConn struct {
	mu         sync.Mutex
	readBuf    elastic.RingBuffer // encrypted data from socket (for tls.Conn to read)
	writeBuf   elastic.RingBuffer // encrypted data to socket (from tls.Conn writes)
	localAddr  net.Addr
	remoteAddr net.Addr
	closed     bool
}

// newBufferConn creates a new buffer-backed net.Conn.
func newBufferConn(localAddr, remoteAddr net.Addr) *bufferConn {
	return &bufferConn{
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}
}

// Read reads encrypted data from the buffer.
// Returns syscall.EAGAIN if no data is available (non-blocking behavior).
func (c *bufferConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return 0, net.ErrClosed
	}

	if c.readBuf.IsEmpty() {
		// Return EAGAIN to signal no data available (non-blocking)
		return 0, syscall.EAGAIN
	}

	return c.readBuf.Read(b)
}

// Write writes encrypted data to the buffer.
// This is called by tls.Conn when it encrypts data.
func (c *bufferConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return 0, net.ErrClosed
	}

	return c.writeBuf.Write(b)
}

// Close marks the connection as closed.
func (c *bufferConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

// close releases buffer resources.
func (c *bufferConn) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	c.readBuf.Done()
	c.writeBuf.Done()
}

// LocalAddr returns the local address.
func (c *bufferConn) LocalAddr() net.Addr {
	return c.localAddr
}

// RemoteAddr returns the remote address.
func (c *bufferConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

// SetDeadline is a no-op for buffer connections.
func (c *bufferConn) SetDeadline(_ time.Time) error {
	return nil
}

// SetReadDeadline is a no-op for buffer connections.
func (c *bufferConn) SetReadDeadline(_ time.Time) error {
	return nil
}

// SetWriteDeadline is a no-op for buffer connections.
func (c *bufferConn) SetWriteDeadline(_ time.Time) error {
	return nil
}

// feedEncryptedData adds encrypted data from the socket to the buffer
// so that tls.Conn can read and decrypt it.
func (c *bufferConn) feedEncryptedData(data []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return 0, net.ErrClosed
	}

	return c.readBuf.Write(data)
}

// hasEncryptedData returns true if there's encrypted data to be read.
func (c *bufferConn) hasEncryptedData() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.readBuf.IsEmpty()
}

// getEncryptedOutput retrieves encrypted data that needs to be written to the socket.
func (c *bufferConn) getEncryptedOutput() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writeBuf.Bytes()
}

// discardEncryptedOutput removes encrypted data that has been written to the socket.
func (c *bufferConn) discardEncryptedOutput(n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, _ = c.writeBuf.Discard(n)
}

// TLS record constants.
const (
	// tlsRecordHeaderSize is 5 bytes: type(1) + version(2) + length(2).
	tlsRecordHeaderSize = 5
	// maxTLSRecordSize is the maximum TLS record size (16KB + overhead).
	maxTLSRecordSize = 16384 + 2048
)

// checkCompleteRecord checks if the buffer contains a complete TLS record.
// Returns the total record size (header + payload) if complete, 0 otherwise.
func checkCompleteRecord(buf *elastic.RingBuffer) int {
	buffered := buf.Buffered()
	if buffered < tlsRecordHeaderSize {
		return 0 // Need at least header
	}

	// Peek at the header
	head, tail := buf.Peek(tlsRecordHeaderSize)
	var header [tlsRecordHeaderSize]byte

	// Copy header bytes (may be split across head and tail)
	n := copy(header[:], head)
	if n < tlsRecordHeaderSize && len(tail) > 0 {
		copy(header[n:], tail)
	}

	// Parse record length from header bytes 3-4 (big-endian)
	recordLen := int(header[3])<<8 | int(header[4])

	// Validate record length
	if recordLen > maxTLSRecordSize {
		return -1 // Invalid record
	}

	totalLen := tlsRecordHeaderSize + recordLen
	if buffered >= totalLen {
		return totalLen
	}

	return 0 // Need more data
}
