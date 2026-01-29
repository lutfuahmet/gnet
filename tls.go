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

package gnet

import (
	"crypto/tls"
	"time"
)

// TLSState represents the state of a TLS connection.
type TLSState int

const (
	// TLSStateNone indicates no TLS is used for this connection.
	TLSStateNone TLSState = iota
	// TLSStateHandshaking indicates the TLS handshake is in progress.
	TLSStateHandshaking
	// TLSStateComplete indicates the TLS handshake completed successfully.
	TLSStateComplete
	// TLSStateFailed indicates the TLS handshake failed.
	TLSStateFailed
)

// DefaultTLSHandshakeTimeout is the default timeout for TLS handshakes.
const DefaultTLSHandshakeTimeout = 30 * time.Second

// TLSConn provides access to TLS-specific connection methods.
// Use type assertion to access these methods: if tc, ok := c.(gnet.TLSConn); ok { ... }.
type TLSConn interface {
	Conn
	// TLSState returns the current TLS state of the connection.
	TLSState() TLSState
	// TLSConnectionState returns the TLS connection state.
	// Returns nil if TLS is not enabled or handshake is not complete.
	TLSConnectionState() *tls.ConnectionState
}
