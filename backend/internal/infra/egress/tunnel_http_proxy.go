package egress

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/chenyme/grok2api/backend/internal/pkg/tunnelproxy"
)

// tunnelHTTPProxy exposes a tunnel proxy (vless/trojan/ss/vmess) as a local
// HTTP CONNECT proxy so browser-based clearance solvers can route through the
// same exit IP that the gateway uses for upstream requests. Cloudflare binds
// clearance cookies to the solving IP, so the browser must egress through the
// tunnel rather than the host's own address.
//
// The listener binds 0.0.0.0 so a solver running in a sibling container can
// reach it; each solve requires fresh proxy credentials. The advertised host is
// resolved separately (see resolveBrowserProxy).
type tunnelHTTPProxy struct {
	listener    net.Listener
	dialer      *tunnelproxy.Dialer
	server      *http.Server
	once        sync.Once
	username    string
	password    string
	mu          sync.Mutex
	closed      bool
	connections map[net.Conn]struct{}
}

func newTunnelHTTPProxy(proxyURL string) (*tunnelHTTPProxy, error) {
	dialer, err := tunnelproxy.NewDialer(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("初始化隧道拨号器: %w", err)
	}
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		return nil, fmt.Errorf("监听本地代理端口: %w", err)
	}
	proxy := &tunnelHTTPProxy{listener: listener, dialer: dialer, username: "clearance", password: rand.Text(), connections: make(map[net.Conn]struct{})}
	proxy.server = &http.Server{
		Handler:           http.HandlerFunc(proxy.handleConnect),
		ReadHeaderTimeout: 30 * time.Second,
	}
	go func() {
		_ = proxy.server.Serve(listener)
	}()
	return proxy, nil
}

func (p *tunnelHTTPProxy) Port() string {
	if p == nil || p.listener == nil {
		return ""
	}
	_, port, err := net.SplitHostPort(p.listener.Addr().String())
	if err != nil {
		return ""
	}
	return port
}

func (p *tunnelHTTPProxy) Close() {
	if p == nil {
		return
	}
	p.once.Do(func() {
		// http.Server.Close does not close hijacked CONNECT connections.
		p.mu.Lock()
		p.closed = true
		for conn := range p.connections {
			_ = conn.Close()
		}
		p.mu.Unlock()
		_ = p.server.Close()
	})
}

func (p *tunnelHTTPProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "only CONNECT is supported", http.StatusMethodNotAllowed)
		return
	}
	expected := "Basic " + base64.StdEncoding.EncodeToString([]byte(p.username+":"+p.password))
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("Proxy-Authorization")), []byte(expected)) != 1 {
		w.Header().Set("Proxy-Authenticate", `Basic realm="clearance"`)
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
		return
	}
	target := r.Host
	if target == "" {
		target = r.URL.Host
	}
	if target == "" {
		http.Error(w, "missing CONNECT target", http.StatusBadRequest)
		return
	}
	upstream, err := p.dialer.DialContext(r.Context(), "tcp", target)
	if err != nil {
		http.Error(w, "tunnel dial failed", http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, buffered, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "hijack failed", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.connections[clientConn] = struct{}{}
	p.mu.Unlock()
	defer func() { p.mu.Lock(); delete(p.connections, clientConn); p.mu.Unlock() }()

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, buffered)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(clientConn, upstream)
		done <- struct{}{}
	}()
	<-done
}

// browserProxy describes a proxy endpoint that a browser-based solver can use.
type browserProxy struct {
	host     string
	port     int
	username string
	password string
	closeFn  func()
}

// resolveBrowserProxy converts a gateway proxy URL into a browser-usable proxy.
// Tunnel schemes are bridged through a local HTTP CONNECT shim; plain HTTP and
// HTTPS proxies are passed through directly. The returned close function must
// be called when the shim is no longer needed.
func resolveBrowserProxy(proxyURL, advertisedHost string) (browserProxy, error) {
	proxyURL = strings.TrimSpace(proxyURL)
	if proxyURL == "" {
		return browserProxy{}, nil
	}
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return browserProxy{}, err
	}
	if tunnelproxy.IsSupportedScheme(parsed.Scheme) {
		shim, shimErr := newTunnelHTTPProxy(proxyURL)
		if shimErr != nil {
			return browserProxy{}, shimErr
		}
		host := strings.TrimSpace(advertisedHost)
		if host == "" {
			host = detectAdvertisedHost()
		}
		port, err := strconv.Atoi(shim.Port())
		if err != nil {
			shim.Close()
			return browserProxy{}, fmt.Errorf("无效的本地代理端口: %w", err)
		}
		return browserProxy{host: host, port: port, username: shim.username, password: shim.password, closeFn: shim.Close}, nil
	}
	switch parsed.Scheme {
	case "http", "https":
		host := parsed.Hostname()
		port := parsed.Port()
		if port == "" {
			if parsed.Scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}
		username := ""
		password := ""
		if parsed.User != nil {
			username = parsed.User.Username()
			password, _ = parsed.User.Password()
		}
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 || host == "" {
			return browserProxy{}, fmt.Errorf("无效的浏览器代理地址")
		}
		return browserProxy{host: host, port: portNumber, username: username, password: password}, nil
	default:
		return browserProxy{}, fmt.Errorf("cf-clearance-scraper 不支持代理协议 %q", parsed.Scheme)
	}
}

// detectAdvertisedHost returns an address that sibling containers can use to
// reach this process. It prefers the container hostname resolved through
// Docker's embedded DNS, then falls back to the first non-loopback IPv4.
func detectAdvertisedHost() string {
	if hostname, err := os.Hostname(); err == nil && hostname != "" {
		if addrs, err := net.LookupHost(hostname); err == nil {
			for _, addr := range addrs {
				if ip := net.ParseIP(addr); ip != nil && !ip.IsLoopback() && ip.To4() != nil {
					return addr
				}
			}
		}
	}
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, addrErr := iface.Addrs()
			if addrErr != nil {
				continue
			}
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok {
					if ip := ipnet.IP.To4(); ip != nil && !ip.IsLoopback() {
						return ip.String()
					}
				}
			}
		}
	}
	return "127.0.0.1"
}
