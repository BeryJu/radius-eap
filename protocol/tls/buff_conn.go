package tls

import (
	"bytes"
	"context"
	"errors"
	"net"
	"time"

	"beryju.io/radius-eap/protocol"
	"github.com/avast/retry-go/v4"
)

type BuffConn struct {
	reader *bytes.Buffer
	writer *bytes.Buffer

	ctx context.Context

	expectedWriterByteCount int
	writtenByteCount        int

	retryOptions []retry.Option
	log          protocol.Logger
}

func NewBuffConn(initialData []byte, ctx context.Context, cctx protocol.Context) *BuffConn {
	c := &BuffConn{
		reader: bytes.NewBuffer(initialData),
		writer: bytes.NewBuffer([]byte{}),
		ctx:    ctx,
		retryOptions: []retry.Option{
			retry.Context(ctx),
			retry.Delay(10 * time.Microsecond),
			retry.DelayType(retry.BackOffDelay),
			retry.MaxDelay(100 * time.Millisecond),
			retry.Attempts(0),
		},
		log: cctx.Log(),
	}
	return c
}

var errStall = errors.New("Stall")

func (conn BuffConn) OutboundData() []byte {
	d, _ := retry.DoWithData(
		func() ([]byte, error) {
			b := conn.writer.Bytes()
			if len(b) < 1 {
				return nil, errStall
			}
			return b, nil
		},
		conn.retryOptions...,
	)
	return d
}

func (conn *BuffConn) UpdateData(data []byte) {
	conn.reader.Write(data)
	conn.writtenByteCount += len(data)
	conn.log.Debug("TLS(buffcon): Appending new data %d (total %d, expecting %d)", len(data), conn.writtenByteCount, conn.expectedWriterByteCount)
}

func (conn BuffConn) NeedsMoreData() bool {
	if conn.expectedWriterByteCount > 0 {
		return conn.reader.Len() < int(conn.expectedWriterByteCount)
	}
	return false
}

func (conn *BuffConn) Read(p []byte) (int, error) {
	d, err := retry.DoWithData(
		func() (int, error) {
			if conn.reader.Len() == 0 {
				conn.log.Debug("TLS(buffcon): Attempted read %d from empty buffer, stalling...", len(p))
				return 0, errStall
			}
			if conn.expectedWriterByteCount > 0 {
				// If we're waiting for more data, we need to stall
				if conn.writtenByteCount < int(conn.expectedWriterByteCount) {
					conn.log.Debug("TLS(buffcon): Attempted read %d while waiting for bytes %d, stalling...", len(p), conn.expectedWriterByteCount-conn.reader.Len())
					return 0, errStall
				}
				// All fragments of the current message have arrived; reset both counters so the
				// next fragmented message starts from a clean slate. Previously only the expected
				// count was reset, which left writtenByteCount inflated by earlier messages and
				// let a later fragmented message be read before it was complete.
				conn.expectedWriterByteCount = 0
				conn.writtenByteCount = 0
			}
			n, err := conn.reader.Read(p)
			conn.log.Debug("TLS(buffcon): Read: %d into %d (total %d)", n, len(p), conn.reader.Len())
			return n, err
		},
		conn.retryOptions...,
	)
	return d, err
}

func (conn BuffConn) Write(p []byte) (int, error) {
	conn.log.Debug("TLS(buffcon): Write: %d", len(p))
	return conn.writer.Write(p)
}

func (conn BuffConn) Close() error                       { return nil }
func (conn BuffConn) LocalAddr() net.Addr                { return nil }
func (conn BuffConn) RemoteAddr() net.Addr               { return nil }
func (conn BuffConn) SetDeadline(t time.Time) error      { return nil }
func (conn BuffConn) SetReadDeadline(t time.Time) error  { return nil }
func (conn BuffConn) SetWriteDeadline(t time.Time) error { return nil }
