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
	"errors"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/panjf2000/gnet/v2/pkg/buffer/elastic"
)

// tlsNonBlockingState manages non-blocking TLS I/O for a connection.
// It wraps a tls.Conn with in-memory buffers to enable non-blocking operations.
type tlsNonBlockingState struct {
	tlsConn *tls.Conn   // the underlying TLS connection (wraps bufConn)
	bufConn *bufferConn // buffer-backed net.Conn for tls.Conn

	// handshakeComplete indicates whether TLS handshake has finished
	handshakeComplete bool
}

// newTLSNonBlockingStateForHandshake creates a new non-blocking TLS state for server-side handshake.
// The tlsConn wraps bufConn, so all I/O goes through buffers, not the raw fd.
func newTLSNonBlockingStateForHandshake(config *tls.Config, localAddr, remoteAddr net.Addr) *tlsNonBlockingState {
	bufConn := newBufferConn(localAddr, remoteAddr)
	tlsConn := tls.Server(bufConn, config)

	return &tlsNonBlockingState{
		tlsConn:           tlsConn,
		bufConn:           bufConn,
		handshakeComplete: false,
	}
}

// newTLSNonBlockingStateForClientHandshake creates a new non-blocking TLS state for client-side handshake.
func newTLSNonBlockingStateForClientHandshake(config *tls.Config, serverName string, localAddr, remoteAddr net.Addr) *tlsNonBlockingState {
	bufConn := newBufferConn(localAddr, remoteAddr)

	// Clone config to set ServerName if needed
	cfg := config
	if serverName != "" && config.ServerName == "" {
		cfg = config.Clone()
		cfg.ServerName = serverName
	}

	tlsConn := tls.Client(bufConn, cfg)

	return &tlsNonBlockingState{
		tlsConn:           tlsConn,
		bufConn:           bufConn,
		handshakeComplete: false,
	}
}

// feedEncryptedData feeds encrypted data from the socket into the TLS layer.
// Returns the number of bytes written.
func (s *tlsNonBlockingState) feedEncryptedData(data []byte) (int, error) {
	return s.bufConn.feedEncryptedData(data)
}

// getEncryptedOutput returns encrypted data that needs to be written to the socket.
func (s *tlsNonBlockingState) getEncryptedOutput() []byte {
	return s.bufConn.getEncryptedOutput()
}

// discardEncryptedOutput discards encrypted output that has been written to the socket.
func (s *tlsNonBlockingState) discardEncryptedOutput(n int) {
	s.bufConn.discardEncryptedOutput(n)
}

// continueHandshake attempts to continue the TLS handshake.
// Returns true if handshake is complete, false if more data is needed.
// Returns error if handshake fails permanently.
func (s *tlsNonBlockingState) continueHandshake() (complete bool, err error) {
	if s.handshakeComplete {
		return true, nil
	}

	err = s.tlsConn.Handshake()
	if err != nil {
		// Check if it's a temporary error (need more data)
		if errors.Is(err, syscall.EAGAIN) {
			return false, nil
		}
		// Check for net.Error timeout (also means need more data)
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return false, nil
		}
		// Permanent error
		return false, err
	}

	s.handshakeComplete = true
	return true, nil
}

// read reads decrypted data from the TLS connection.
// Returns syscall.EAGAIN if no data is available.
func (s *tlsNonBlockingState) read(buf []byte) (int, error) {
	if !s.handshakeComplete {
		return 0, errors.New("handshake not complete")
	}

	n, err := s.tlsConn.Read(buf)
	if err != nil {
		// Convert EAGAIN to indicate need more encrypted data
		if errors.Is(err, syscall.EAGAIN) {
			return 0, syscall.EAGAIN
		}
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return 0, syscall.EAGAIN
		}
		return n, err
	}
	return n, nil
}

// write encrypts and buffers data for sending.
// The encrypted data should be retrieved with getEncryptedOutput().
func (s *tlsNonBlockingState) write(data []byte) (int, error) {
	if !s.handshakeComplete {
		return 0, errors.New("handshake not complete")
	}
	return s.tlsConn.Write(data)
}

// release cleans up the TLS non-blocking state resources.
func (s *tlsNonBlockingState) release() {
	if s.tlsConn != nil {
		_ = s.tlsConn.Close()
		s.tlsConn = nil
	}
	if s.bufConn != nil {
		s.bufConn.close()
		s.bufConn = nil
	}
}

// connectionState returns the TLS connection state.
func (s *tlsNonBlockingState) connectionState() tls.ConnectionState {
	if s.tlsConn != nil {
		return s.tlsConn.ConnectionState()
	}
	return tls.ConnectionState{}
}

// newTLSNonBlockingStateFromConn creates a non-blocking TLS state from an already-handshaked tls.Conn.
// This is used for client-side connections where blocking handshake is acceptable.
// Note: The tlsConn must have completed handshake and wraps the original fdConn.
// For post-handshake non-blocking I/O, we use bufConn but the initial tlsConn still wraps fdConn.
// This hybrid approach works because we bypass the bufConn and read directly through tlsConn for clients.
func newTLSNonBlockingStateFromConn(tlsConn *tls.Conn, localAddr, remoteAddr net.Addr) *tlsNonBlockingState {
	bufConn := newBufferConn(localAddr, remoteAddr)
	return &tlsNonBlockingState{
		tlsConn:           tlsConn,
		bufConn:           bufConn,
		handshakeComplete: true, // Already completed
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

// hasEncryptedOutput returns true if there's encrypted data to write to socket.
func (c *bufferConn) hasEncryptedOutput() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.writeBuf.IsEmpty()
}
