package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"runtime/debug"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/whoisnian/glb/logger"
	"github.com/whoisnian/glb/util/fsutil"
	"github.com/whoisnian/glp/global"
	xproxy "golang.org/x/net/proxy"
)

var ErrServerClosed = errors.New("proxy: server closed")

type Server struct {
	addr  string
	proxy string
	klogw io.WriteCloser

	listener  net.Listener
	dialer    xproxy.Dialer
	transport *http.Transport

	shutdown    atomic.Bool
	listenerWg  sync.WaitGroup
	trackedConn map[*BufioConn]context.CancelFunc
	mu          sync.Mutex
}

func NewServer(addr string, proxy string, klogf string) (s *Server, err error) {
	s = &Server{addr: addr, proxy: proxy}
	if klogf != "" {
		fpath, err := fsutil.ExpandHomeDir(klogf)
		if err != nil {
			return nil, fmt.Errorf("fsutil.ExpandHomeDir: %w", err)
		}
		if s.klogw, err = os.Create(fpath); err != nil {
			return nil, fmt.Errorf("os.Create: %w", err)
		}
	}
	s.dialer, s.transport, err = parseProxy(proxy)
	return s, err
}

func (s *Server) ListenAndServe() (err error) {
	if s.shutdown.Load() {
		return ErrServerClosed
	}
	if s.listener != nil {
		return errors.New("proxy: server already listening")
	}

	s.listenerWg.Add(1)
	defer s.listenerWg.Done()
	s.listener, err = net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.shutdown.Load() {
				return ErrServerClosed
			}
			return err
		}
		go s.serve(conn)
	}
}

func (s *Server) serve(conn net.Conn) {
	ctx, cancel := context.WithCancel(context.Background())
	bufioConn := NewBufioConn(conn)
	defer func() {
		if err := recover(); err != nil {
			global.LOG.Errorf(ctx, "proxy: panic serving %v: %v\n%s", conn.RemoteAddr(), err, debug.Stack())
		}
		bufioConn.Close()
		s.trackConn(bufioConn, cancel, false)
	}()
	s.trackConn(bufioConn, cancel, true)

	req, err := http.ReadRequest(bufioConn.Reader())
	if err != nil {
		global.LOG.Error(ctx, "http.ReadRequest", logger.Error(err))
		return
	}
	req = req.WithContext(ctx)

	if req.URL.Host == "" {
		s.handleRequest(bufioConn, req)
	} else if req.Method == http.MethodConnect {
		bufioConn.Write([]byte("HTTP/1.1 200 Connection established\r\nContent-Length: 0\r\n\r\n"))

		if data, err := bufioConn.Reader().Peek(8); err != nil {
			global.LOG.Warnf(ctx, "proxy: fallback to tcp error %v", err)
			s.handleTCP(bufioConn, req, false)
		} else if sniffTLSHandshakePrefix(data) {
			s.handleTLS(bufioConn, req)
		} else if sniffHTTPMethodPrefix(data) {
			s.handleHTTP(bufioConn, req)
		} else {
			global.LOG.Warnf(ctx, "proxy: fallback to tcp unknown %s", strconv.QuoteToGraphic(string(data)))
			s.handleTCP(bufioConn, req, false)
		}
	} else {
		s.handleHTTP(bufioConn, req)
	}
}

func (s *Server) trackConn(conn *BufioConn, cancel context.CancelFunc, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.trackedConn == nil {
		s.trackedConn = make(map[*BufioConn]context.CancelFunc)
	}
	if add {
		s.trackedConn[conn] = cancel
	} else {
		delete(s.trackedConn, conn)
	}
}

func (s *Server) Shutdown(ctx context.Context) (err error) {
	s.shutdown.Store(true)
	err = s.listener.Close()
	s.listenerWg.Wait()

	if s.klogw != nil && err == nil {
		err = s.klogw.Close()
	} else if s.klogw != nil {
		if err2 := s.klogw.Close(); err2 != nil {
			global.LOG.Warn(ctx, "klogw.Close", logger.Error(err2))
		}
	}

	// https://cs.opensource.google/go/go/+/refs/tags/go1.24.3:src/net/http/server.go;l=3151
	pollIntervalBase := time.Millisecond
	nextPollInterval := func() time.Duration {
		interval := pollIntervalBase + time.Duration(rand.Intn(int(pollIntervalBase/10)))
		pollIntervalBase *= 2
		if pollIntervalBase > 500*time.Millisecond {
			pollIntervalBase = 500 * time.Millisecond
		}
		return interval
	}

	timer := time.NewTimer(nextPollInterval())
	defer timer.Stop()
	for {
		if s.notifyTrackedConns() {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			timer.Reset(nextPollInterval())
		}
	}
}

func (s *Server) notifyTrackedConns() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	done := true
	for _, cancel := range s.trackedConn {
		done = false
		cancel()
	}
	return done
}
