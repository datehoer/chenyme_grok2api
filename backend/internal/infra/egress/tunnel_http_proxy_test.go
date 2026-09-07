package egress

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	singvless "github.com/metacubex/sing-vmess/vless"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestScraperTunnelProxyAuthenticationForwardingAndCleanup(t *testing.T) {
	tunnel, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := tunnel.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		request, err := singvless.ReadRequest(conn)
		if err != nil {
			done <- err
			return
		}
		if request.Destination.Fqdn != "target.example" || request.Destination.Port != 443 {
			done <- fmt.Errorf("unexpected tunnel destination")
			return
		}
		if _, err = conn.Write([]byte{0, 0}); err == nil {
			_, err = io.Copy(conn, conn)
		}
		done <- err
	}()
	var client net.Conn
	var address string
	scraper := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Proxy struct {
				Host     string
				Port     int
				Username string
				Password string
			}
		}
		fail := func(err error) { t.Error(err); http.Error(w, "test failure", 500) }
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			fail(err)
			return
		}
		p := payload.Proxy
		if p.Port < 1 || p.Username == "" || len(p.Password) < 26 {
			fail(fmt.Errorf("missing proxy credentials or integer port"))
			return
		}
		address = net.JoinHostPort(p.Host, strconv.Itoa(p.Port))
		auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(p.Username+":"+p.Password))
		for _, header := range []string{"", "Basic invalid", auth} {
			conn, err := net.DialTimeout("tcp", address, time.Second)
			if err != nil {
				fail(err)
				return
			}
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			_, _ = fmt.Fprintf(conn, "CONNECT target.example:443 HTTP/1.1\r\nHost: target.example:443\r\nProxy-Authorization: %s\r\n\r\nping", header)
			reader := bufio.NewReader(conn)
			response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
			if err != nil {
				conn.Close()
				fail(err)
				return
			}
			if header != auth {
				if response.StatusCode != 407 || response.Header.Get("Proxy-Authenticate") == "" {
					fail(fmt.Errorf("unauthorized CONNECT was not challenged"))
					conn.Close()
					return
				}
				response.Body.Close()
				conn.Close()
				continue
			}
			client = conn
			if response.StatusCode != 200 {
				fail(fmt.Errorf("authorized CONNECT failed"))
				return
			}
			data := make([]byte, 4)
			if _, err := io.ReadFull(reader, data); err != nil || string(data) != "ping" {
				fail(fmt.Errorf("echo = %q: %v", data, err))
				return
			}
		}
		_, _ = io.WriteString(w, `{"code":200,"cookies":[],"headers":{"user-agent":"test-browser"}}`)
	}))
	defer scraper.Close()
	_, err = (cfClearanceScraperSolver{}).Solve(context.Background(), ClearanceConfig{ClearanceSolverURL: scraper.URL, Timeout: 5 * time.Second}, "vless://e6edbfc0-6d1c-43c5-a3fc-8d07024fdcf1@"+tunnel.Addr().String()+"?security=none")
	if client != nil {
		defer client.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("CONNECT not closed after solve: %v", err)
	}
	if conn, err := net.DialTimeout("tcp", address, time.Second); err == nil {
		conn.Close()
		t.Fatal("proxy listener still open")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("upstream tunnel still open")
	}
}

func TestTunnelProxyCredentialsArePerSolve(t *testing.T) {
	url := "vless://e6edbfc0-6d1c-43c5-a3fc-8d07024fdcf1@127.0.0.1:1?security=none"
	a, err := resolveBrowserProxy(url, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer a.closeFn()
	b, err := resolveBrowserProxy(url, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer b.closeFn()
	if a.password == "" || a.password == b.password {
		t.Fatal("credentials reused")
	}
}
