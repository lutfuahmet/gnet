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
	"os"
	"time"
)

// fdConn wraps a file descriptor as a net.Conn for use with crypto/tls.
// This allows us to use the standard TLS library with raw file descriptors.
type fdConn struct {
	fd         int
	file       *os.File
	localAddr  net.Addr
	remoteAddr net.Addr
}

// newFDConn creates a new fdConn from a file descriptor.
func newFDConn(fd int, localAddr, remoteAddr net.Addr) (*fdConn, error) {
	// Create a file from the fd for reading/writing
	file := os.NewFile(uintptr(fd), "socket")
	if file == nil {
		return nil, os.ErrInvalid
	}
	return &fdConn{
		fd:         fd,
		file:       file,
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}, nil
}

func (c *fdConn) Read(b []byte) (int, error) {
	return c.file.Read(b)
}

func (c *fdConn) Write(b []byte) (int, error) {
	return c.file.Write(b)
}

func (c *fdConn) Close() error {
	// Don't close the file here as it would close the underlying fd
	// which we want to keep open for the event loop
	return nil
}

func (c *fdConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *fdConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *fdConn) SetDeadline(t time.Time) error {
	return c.file.SetDeadline(t)
}

func (c *fdConn) SetReadDeadline(t time.Time) error {
	return c.file.SetReadDeadline(t)
}

func (c *fdConn) SetWriteDeadline(t time.Time) error {
	return c.file.SetWriteDeadline(t)
}

// performServerTLSHandshake performs a TLS handshake for server-side connections.
// This function blocks during the handshake and should be called from a goroutine pool.
func performServerTLSHandshake(fd int, config *tls.Config, localAddr, remoteAddr net.Addr, timeout time.Duration) (*tls.Conn, error) {
	fdConn, err := newFDConn(fd, localAddr, remoteAddr)
	if err != nil {
		return nil, err
	}

	tlsConn := tls.Server(fdConn, config)

	// Set handshake deadline
	if timeout > 0 {
		if err := tlsConn.SetDeadline(time.Now().Add(timeout)); err != nil {
			return nil, err
		}
	}

	// Perform the handshake
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}

	// Clear the deadline after successful handshake
	if err := tlsConn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}

	return tlsConn, nil
}

// performClientTLSHandshake performs a TLS handshake for client-side connections.
// This function blocks during the handshake and should be called from a goroutine pool.
func performClientTLSHandshake(fd int, config *tls.Config, serverName string, localAddr, remoteAddr net.Addr, timeout time.Duration) (*tls.Conn, error) {
	fdConn, err := newFDConn(fd, localAddr, remoteAddr)
	if err != nil {
		return nil, err
	}

	// Clone the config to set ServerName if needed
	cfg := config
	if serverName != "" && config.ServerName == "" {
		cfg = config.Clone()
		cfg.ServerName = serverName
	}

	tlsConn := tls.Client(fdConn, cfg)

	// Set handshake deadline
	if timeout > 0 {
		if err := tlsConn.SetDeadline(time.Now().Add(timeout)); err != nil {
			return nil, err
		}
	}

	// Perform the handshake
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}

	// Clear the deadline after successful handshake
	if err := tlsConn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}

	return tlsConn, nil
}

// getTLSHandshakeTimeout returns the configured TLS handshake timeout or the default.
func getTLSHandshakeTimeout(opts *Options) time.Duration {
	if opts.TLSHandshakeTimeout > 0 {
		return opts.TLSHandshakeTimeout
	}
	return DefaultTLSHandshakeTimeout
}
