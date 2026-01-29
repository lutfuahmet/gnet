// Copyright (c) 2021 The Gnet Authors. All rights reserved.
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
	"runtime"

	"golang.org/x/sys/unix"

	"github.com/panjf2000/gnet/v2/pkg/errors"
	"github.com/panjf2000/gnet/v2/pkg/netpoll"
	"github.com/panjf2000/gnet/v2/pkg/pool/goroutine"
	"github.com/panjf2000/gnet/v2/pkg/queue"
	"github.com/panjf2000/gnet/v2/pkg/socket"
)

func (el *eventloop) accept0(fd int, _ netpoll.IOEvent, _ netpoll.IOFlags) error {
	for {
		nfd, sa, err := socket.Accept(fd)
		switch err {
		case nil:
		case unix.EAGAIN: // the Accept queue has been drained out, we can return now
			return nil
		case unix.EINTR, unix.ECONNRESET, unix.ECONNABORTED:
			// ECONNRESET or ECONNABORTED could indicate that a socket
			// in the Accept queue was closed before we Accept()ed it.
			// It's a silly error, let's retry it.
			continue
		default:
			el.getLogger().Errorf("Accept() failed due to error: %v", err)
			return errors.ErrAcceptSocket
		}

		remoteAddr := socket.SockaddrToTCPOrUnixAddr(sa)
		network := el.listeners[fd].network
		opts := el.engine.opts
		if opts.TCPKeepAlive > 0 && network == "tcp" &&
			(runtime.GOOS != "linux" && runtime.GOOS != "freebsd" && runtime.GOOS != "dragonfly") {
			// TCP keepalive options are not inherited from the listening socket
			// on platforms other than Linux, FreeBSD, or DragonFlyBSD.
			// We therefore need to set them on the accepted socket explicitly.
			//
			// Check out https://github.com/nginx/nginx/pull/337 for details.
			if err = setKeepAlive(
				nfd,
				true,
				opts.TCPKeepAlive,
				opts.TCPKeepInterval,
				opts.TCPKeepCount); err != nil {
				el.getLogger().Errorf("failed to set TCP keepalive on fd=%d: %v", fd, err)
			}
		}

		targetEl := el.engine.eventLoops.next(remoteAddr)
		localAddr := el.listeners[fd].addr
		c := newStreamConn(network, nfd, targetEl, sa, localAddr, remoteAddr)

		// Handle TLS if configured
		if opts.TLSConfig != nil && network != "udp" {
			c.tlsState = TLSStateHandshaking
			// Offload TLS handshake to goroutine pool to avoid blocking the event loop
			err = goroutine.DefaultWorkerPool.Submit(func() {
				el.performTLSHandshakeAndRegister(c, opts, targetEl)
			})
			if err != nil {
				el.getLogger().Errorf("failed to submit TLS handshake job for fd=%d: %v", c.fd, err)
				_ = unix.Close(nfd)
				c.release()
			}
		} else {
			err = targetEl.poller.Trigger(queue.HighPriority, targetEl.register, c)
			if err != nil {
				el.getLogger().Errorf("failed to enqueue the accepted socket fd=%d to poller: %v", c.fd, err)
				_ = unix.Close(nfd)
				c.release()
			}
		}
	}
}

// performTLSHandshakeAndRegister performs TLS handshake in a goroutine and registers
// the connection to the event loop upon successful completion.
func (el *eventloop) performTLSHandshakeAndRegister(c *conn, opts *Options, targetEl *eventloop) {
	timeout := getTLSHandshakeTimeout(opts)
	tlsConn, err := performServerTLSHandshake(c.fd, opts.TLSConfig, c.localAddr, c.remoteAddr, timeout)
	if err != nil {
		el.getLogger().Errorf("TLS handshake failed for fd=%d: %v", c.fd, err)
		c.tlsState = TLSStateFailed
		_ = unix.Close(c.fd)
		c.release()
		return
	}

	// Create the non-blocking TLS state for post-handshake I/O
	c.tlsNB = newTLSNonBlockingState(tlsConn, c.localAddr, c.remoteAddr)
	c.tlsConn = tlsConn // Keep reference for ConnectionState access
	c.tlsState = TLSStateComplete

	// Register the connection to the event loop
	err = targetEl.poller.Trigger(queue.HighPriority, targetEl.register, c)
	if err != nil {
		el.getLogger().Errorf("failed to enqueue TLS connection fd=%d to poller: %v", c.fd, err)
		c.tlsNB.release()
		c.tlsNB = nil
		_ = tlsConn.Close()
		_ = unix.Close(c.fd)
		c.release()
	}
}

func (el *eventloop) accept(fd int, ev netpoll.IOEvent, flags netpoll.IOFlags) error {
	network := el.listeners[fd].network
	if network == "udp" {
		return el.readUDP(fd, ev, flags)
	}

	nfd, sa, err := socket.Accept(fd)
	switch err {
	case nil:
	case unix.EINTR, unix.EAGAIN, unix.ECONNRESET, unix.ECONNABORTED:
		// ECONNRESET or ECONNABORTED could indicate that a socket
		// in the Accept queue was closed before we Accept()ed it.
		// It's a silly error, let's retry it.
		return nil
	default:
		el.getLogger().Errorf("Accept() failed due to error: %v", err)
		return errors.ErrAcceptSocket
	}

	remoteAddr := socket.SockaddrToTCPOrUnixAddr(sa)
	opts := el.engine.opts
	if opts.TCPKeepAlive > 0 && network == "tcp" &&
		(runtime.GOOS != "linux" && runtime.GOOS != "freebsd" && runtime.GOOS != "dragonfly") {
		// TCP keepalive options are not inherited from the listening socket
		// on platforms other than Linux, FreeBSD, or DragonFlyBSD.
		// We therefore need to set them on the accepted socket explicitly.
		//
		// Check out https://github.com/nginx/nginx/pull/337 for details.
		if err = setKeepAlive(
			nfd,
			true,
			opts.TCPKeepAlive,
			opts.TCPKeepInterval,
			opts.TCPKeepCount); err != nil {
			el.getLogger().Errorf("failed to set TCP keepalive on fd=%d: %v", fd, err)
		}
	}

	c := newStreamConn(network, nfd, el, sa, el.listeners[fd].addr, remoteAddr)

	// Handle TLS if configured
	if opts.TLSConfig != nil && network != "udp" {
		c.tlsState = TLSStateHandshaking
		// Offload TLS handshake to goroutine pool to avoid blocking the event loop
		err = goroutine.DefaultWorkerPool.Submit(func() {
			el.performTLSHandshakeAndRegister(c, opts, el)
		})
		if err != nil {
			el.getLogger().Errorf("failed to submit TLS handshake job for fd=%d: %v", c.fd, err)
			_ = unix.Close(nfd)
			c.release()
			return nil
		}
		return nil
	}

	return el.register0(c)
}
