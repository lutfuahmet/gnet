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
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"

	"github.com/panjf2000/gnet/v2/pkg/buffer/ring"
	errorx "github.com/panjf2000/gnet/v2/pkg/errors"
	"github.com/panjf2000/gnet/v2/pkg/logging"
	"github.com/panjf2000/gnet/v2/pkg/math"
	"github.com/panjf2000/gnet/v2/pkg/netpoll"
	"github.com/panjf2000/gnet/v2/pkg/queue"
	"github.com/panjf2000/gnet/v2/pkg/socket"
)

// Client of gnet.
type Client struct {
	opts *Options
	eng  *engine
}

// NewClient creates an instance of Client.
func NewClient(eh EventHandler, opts ...Option) (cli *Client, err error) {
	options := loadOptions(opts...)
	cli = new(Client)
	cli.opts = options

	logger, logFlusher := logging.GetDefaultLogger(), logging.GetDefaultFlusher()
	if options.Logger == nil {
		if options.LogPath != "" {
			logger, logFlusher, _ = logging.CreateLoggerAsLocalFile(options.LogPath, options.LogLevel)
		}
		options.Logger = logger
	} else {
		logger = options.Logger
		logFlusher = nil
	}
	logging.SetDefaultLoggerAndFlusher(logger, logFlusher)

	rootCtx, shutdown := context.WithCancel(context.Background())
	eg, ctx := errgroup.WithContext(rootCtx)
	eng := engine{
		listeners:    make(map[int]*listener),
		opts:         options,
		turnOff:      shutdown,
		eventHandler: eh,
		eventLoops:   new(leastConnectionsLoadBalancer),
		concurrency: struct {
			*errgroup.Group
			ctx context.Context
		}{eg, ctx},
	}

	if options.EdgeTriggeredIOChunk > 0 {
		options.EdgeTriggeredIO = true
		options.EdgeTriggeredIOChunk = math.CeilToPowerOfTwo(options.EdgeTriggeredIOChunk)
	} else if options.EdgeTriggeredIO {
		options.EdgeTriggeredIOChunk = 1 << 20 // 1MB
	}

	rbc := options.ReadBufferCap
	switch {
	case rbc <= 0:
		options.ReadBufferCap = MaxStreamBufferCap
	case rbc <= ring.DefaultBufferSize:
		options.ReadBufferCap = ring.DefaultBufferSize
	default:
		options.ReadBufferCap = math.CeilToPowerOfTwo(rbc)
	}
	wbc := options.WriteBufferCap
	switch {
	case wbc <= 0:
		options.WriteBufferCap = MaxStreamBufferCap
	case wbc <= ring.DefaultBufferSize:
		options.WriteBufferCap = ring.DefaultBufferSize
	default:
		options.WriteBufferCap = math.CeilToPowerOfTwo(wbc)
	}
	cli.eng = &eng
	return
}

// Start starts the client event-loop, handing IO events.
func (cli *Client) Start() error {
	numEventLoop := determineEventLoops(cli.opts)
	logging.Infof("Starting gnet client with %d event loops", numEventLoop)

	cli.eng.eventHandler.OnBoot(Engine{cli.eng})

	var el0 *eventloop
	for i := 0; i < numEventLoop; i++ {
		p, err := netpoll.OpenPoller()
		if err != nil {
			cli.eng.closeEventLoops()
			return err
		}
		el := eventloop{
			listeners:    cli.eng.listeners,
			engine:       cli.eng,
			poller:       p,
			buffer:       make([]byte, cli.opts.ReadBufferCap),
			eventHandler: cli.eng.eventHandler,
		}
		el.connections.init()
		cli.eng.eventLoops.register(&el)
		if cli.opts.Ticker && el.idx == 0 {
			el0 = &el
		}
	}

	cli.eng.eventLoops.iterate(func(_ int, el *eventloop) bool {
		cli.eng.concurrency.Go(el.run)
		return true
	})

	// Start the ticker.
	if el0 != nil {
		ctx := cli.eng.concurrency.ctx
		cli.eng.concurrency.Go(func() error {
			el0.ticker(ctx)
			return nil
		})
	}

	logging.Debugf("default logging level is %s", logging.LogLevel())

	return nil
}

// Stop stops the client event-loop.
func (cli *Client) Stop() error {
	cli.eng.shutdown(nil)

	cli.eng.eventHandler.OnShutdown(Engine{cli.eng})

	// Notify all event-loops to exit.
	cli.eng.eventLoops.iterate(func(_ int, el *eventloop) bool {
		logging.Error(el.poller.Trigger(queue.HighPriority,
			func(_ any) error { return errorx.ErrEngineShutdown }, nil))
		return true
	})

	// Wait for all event-loops to exit.
	err := cli.eng.concurrency.Wait()

	cli.eng.closeEventLoops()

	// Put the engine into the shutdown state.
	cli.eng.inShutdown.Store(true)

	// Flush the logger.
	logging.Cleanup()

	return err
}

// Dial is like net.Dial().
func (cli *Client) Dial(network, address string) (Conn, error) {
	return cli.DialContext(network, address, nil)
}

// DialTLS is like Dial but uses the provided TLS config for the connection.
// This overrides the client's TLSConfig for this specific connection.
func (cli *Client) DialTLS(network, address string, tlsConfig *tls.Config) (Conn, error) {
	return cli.DialTLSContext(network, address, nil, tlsConfig)
}

// DialTLSContext is like DialTLS but also accepts an empty interface ctx.
func (cli *Client) DialTLSContext(network, address string, ctx any, tlsConfig *tls.Config) (Conn, error) {
	c, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}
	return cli.enrollWithTLS(c, ctx, tlsConfig, extractHostFromAddr(address))
}

// DialContext is like Dial but also accepts an empty interface ctx that can be obtained later via Conn.Context.
func (cli *Client) DialContext(network, address string, ctx any) (Conn, error) {
	c, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}
	return cli.EnrollContext(c, ctx)
}

// Enroll converts a net.Conn to gnet.Conn and then adds it into the Client.
func (cli *Client) Enroll(c net.Conn) (Conn, error) {
	return cli.EnrollContext(c, nil)
}

// EnrollContext is like Enroll but also accepts an empty interface ctx that can be obtained later via Conn.Context.
func (cli *Client) EnrollContext(c net.Conn, ctx any) (Conn, error) {
	defer c.Close() //nolint:errcheck

	sc, ok := c.(syscall.Conn)
	if !ok {
		return nil, errors.New("failed to convert net.Conn to syscall.Conn")
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return nil, errors.New("failed to get syscall.RawConn from net.Conn")
	}

	var dupFD int
	e := rc.Control(func(fd uintptr) {
		dupFD, err = socket.Dup(int(fd))
	})
	if err != nil {
		return nil, err
	}
	if e != nil {
		return nil, e
	}

	if cli.opts.SocketSendBuffer > 0 {
		if err = socket.SetSendBuffer(dupFD, cli.opts.SocketSendBuffer); err != nil {
			return nil, err
		}
	}
	if cli.opts.SocketRecvBuffer > 0 {
		if err = socket.SetRecvBuffer(dupFD, cli.opts.SocketRecvBuffer); err != nil {
			return nil, err
		}
	}

	el := cli.eng.eventLoops.next(nil)
	var (
		sockAddr   unix.Sockaddr
		gc         *conn
		network    string
		serverName string
	)
	switch c.(type) {
	case *net.UnixConn:
		network = "unix"
		sockAddr, _, _, err = socket.GetUnixSockAddr(c.RemoteAddr().Network(), c.RemoteAddr().String())
		if err != nil {
			return nil, err
		}
		ua := c.LocalAddr().(*net.UnixAddr)
		ua.Name = c.RemoteAddr().String() + "." + strconv.Itoa(dupFD)
		gc = newStreamConn(network, dupFD, el, sockAddr, c.LocalAddr(), c.RemoteAddr())
	case *net.TCPConn:
		network = "tcp"
		if cli.opts.TCPNoDelay == TCPNoDelay {
			if err = socket.SetNoDelay(dupFD, 1); err != nil {
				return nil, err
			}
		}
		if cli.opts.TCPKeepAlive > 0 {
			if err = setKeepAlive(
				dupFD,
				true,
				cli.opts.TCPKeepAlive,
				cli.opts.TCPKeepInterval,
				cli.opts.TCPKeepCount); err != nil {
				return nil, err
			}
		}
		sockAddr, _, _, _, err = socket.GetTCPSockAddr(c.RemoteAddr().Network(), c.RemoteAddr().String())
		if err != nil {
			return nil, err
		}
		gc = newStreamConn(network, dupFD, el, sockAddr, c.LocalAddr(), c.RemoteAddr())
		// Extract server name from remote address for TLS
		if addr := c.RemoteAddr().String(); addr != "" {
			serverName = extractHostFromAddr(addr)
		}
	case *net.UDPConn:
		network = "udp"
		sockAddr, _, _, _, err = socket.GetUDPSockAddr(c.RemoteAddr().Network(), c.RemoteAddr().String())
		if err != nil {
			return nil, err
		}
		gc = newUDPConn(dupFD, el, c.LocalAddr(), sockAddr, true)
	default:
		return nil, errorx.ErrUnsupportedProtocol
	}
	gc.ctx = ctx

	// Handle TLS if configured (only for stream protocols)
	if cli.opts.TLSConfig != nil && network != "udp" {
		gc.tlsState = TLSStateHandshaking
		timeout := getTLSHandshakeTimeout(cli.opts)
		tlsConn, err := performClientTLSHandshake(dupFD, cli.opts.TLSConfig, serverName, gc.localAddr, gc.remoteAddr, timeout)
		if err != nil {
			_ = unix.Close(dupFD)
			gc.release()
			return nil, err
		}
		// Create the non-blocking TLS state for post-handshake I/O
		gc.tlsNB = newTLSNonBlockingState(tlsConn, gc.localAddr, gc.remoteAddr)
		gc.tlsConn = tlsConn // Keep reference for ConnectionState access
		gc.tlsState = TLSStateComplete
	}

	connOpened := make(chan struct{})
	ccb := &connWithCallback{c: gc, cb: func() {
		close(connOpened)
	}}
	err = el.poller.Trigger(queue.HighPriority, el.register, ccb)
	if err != nil {
		gc.Close() //nolint:errcheck
		return nil, err
	}
	<-connOpened

	return gc, nil
}

// extractHostFromAddr extracts the hostname from an address string (host:port format).
func extractHostFromAddr(addr string) string {
	// Handle IPv6 addresses like [::1]:8080
	if strings.HasPrefix(addr, "[") {
		if idx := strings.LastIndex(addr, "]:"); idx != -1 {
			return addr[1:idx]
		}
		return strings.TrimPrefix(strings.TrimSuffix(addr, "]"), "[")
	}
	// Handle regular addresses like localhost:8080
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		return addr[:idx]
	}
	return addr
}

// enrollWithTLS enrolls a connection with explicit TLS configuration.
func (cli *Client) enrollWithTLS(c net.Conn, ctx any, tlsConfig *tls.Config, serverName string) (Conn, error) {
	defer c.Close() //nolint:errcheck

	sc, ok := c.(syscall.Conn)
	if !ok {
		return nil, errors.New("failed to convert net.Conn to syscall.Conn")
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return nil, errors.New("failed to get syscall.RawConn from net.Conn")
	}

	var dupFD int
	e := rc.Control(func(fd uintptr) {
		dupFD, err = socket.Dup(int(fd))
	})
	if err != nil {
		return nil, err
	}
	if e != nil {
		return nil, e
	}

	if cli.opts.SocketSendBuffer > 0 {
		if err = socket.SetSendBuffer(dupFD, cli.opts.SocketSendBuffer); err != nil {
			return nil, err
		}
	}
	if cli.opts.SocketRecvBuffer > 0 {
		if err = socket.SetRecvBuffer(dupFD, cli.opts.SocketRecvBuffer); err != nil {
			return nil, err
		}
	}

	el := cli.eng.eventLoops.next(nil)
	var (
		sockAddr unix.Sockaddr
		gc       *conn
		network  string
	)
	switch c.(type) {
	case *net.UnixConn:
		network = "unix"
		sockAddr, _, _, err = socket.GetUnixSockAddr(c.RemoteAddr().Network(), c.RemoteAddr().String())
		if err != nil {
			return nil, err
		}
		ua := c.LocalAddr().(*net.UnixAddr)
		ua.Name = c.RemoteAddr().String() + "." + strconv.Itoa(dupFD)
		gc = newStreamConn(network, dupFD, el, sockAddr, c.LocalAddr(), c.RemoteAddr())
	case *net.TCPConn:
		network = "tcp"
		if cli.opts.TCPNoDelay == TCPNoDelay {
			if err = socket.SetNoDelay(dupFD, 1); err != nil {
				return nil, err
			}
		}
		if cli.opts.TCPKeepAlive > 0 {
			if err = setKeepAlive(
				dupFD,
				true,
				cli.opts.TCPKeepAlive,
				cli.opts.TCPKeepInterval,
				cli.opts.TCPKeepCount); err != nil {
				return nil, err
			}
		}
		sockAddr, _, _, _, err = socket.GetTCPSockAddr(c.RemoteAddr().Network(), c.RemoteAddr().String())
		if err != nil {
			return nil, err
		}
		gc = newStreamConn(network, dupFD, el, sockAddr, c.LocalAddr(), c.RemoteAddr())
	case *net.UDPConn:
		_ = unix.Close(dupFD)
		return nil, errors.New("TLS is not supported for UDP connections")
	default:
		return nil, errorx.ErrUnsupportedProtocol
	}
	gc.ctx = ctx

	// Perform TLS handshake
	gc.tlsState = TLSStateHandshaking
	timeout := getTLSHandshakeTimeout(cli.opts)
	tlsConn, err := performClientTLSHandshake(dupFD, tlsConfig, serverName, gc.localAddr, gc.remoteAddr, timeout)
	if err != nil {
		_ = unix.Close(dupFD)
		gc.release()
		return nil, err
	}
	// Create the non-blocking TLS state for post-handshake I/O
	gc.tlsNB = newTLSNonBlockingState(tlsConn, gc.localAddr, gc.remoteAddr)
	gc.tlsConn = tlsConn // Keep reference for ConnectionState access
	gc.tlsState = TLSStateComplete

	connOpened := make(chan struct{})
	ccb := &connWithCallback{c: gc, cb: func() {
		close(connOpened)
	}}
	err = el.poller.Trigger(queue.HighPriority, el.register, ccb)
	if err != nil {
		gc.Close() //nolint:errcheck
		return nil, err
	}
	<-connOpened

	return gc, nil
}
