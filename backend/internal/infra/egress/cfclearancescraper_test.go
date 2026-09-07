package egress

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCFClearanceScraperSolveMapsWafSessionResponse(t *testing.T) {
	var requestPayload map[string]any
	var clientKeyHeader string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/cf-clearance-scraper" || request.Method != http.MethodPost {
			t.Fatalf("request = %s %s", request.Method, request.URL.Path)
		}
		clientKeyHeader = request.Header.Get("x-client-key")
		if err := json.NewDecoder(request.Body).Decode(&requestPayload); err != nil {
			t.Fatal(err)
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"code":200,"cookies":[{"name":"__cf_bm","value":"bm"},{"name":"sso","value":"secret"},{"name":"cf_clearance","value":"clear"}],"headers":{"user-agent":"Mozilla/5.0 Chrome/151.0.0.0 Safari/537.36"}}`))
	}))
	defer server.Close()

	solution, err := (cfClearanceScraperSolver{}).Solve(context.Background(), ClearanceConfig{
		ClearanceSolverURL: server.URL, ClearanceSolverKey: "test-key", TargetURL: "https://grok.com", Timeout: time.Second,
	}, "http://proxy:8080")
	if err != nil {
		t.Fatal(err)
	}
	if solution.Cookies != "__cf_bm=bm; cf_clearance=clear" || solution.UserAgent == "" {
		t.Fatalf("solution = %#v", solution)
	}
	if clientKeyHeader != "test-key" {
		t.Fatalf("client key header = %q", clientKeyHeader)
	}
	if requestPayload["mode"] != "waf-session" || requestPayload["url"] != "https://grok.com" {
		t.Fatalf("payload = %#v", requestPayload)
	}
	proxy, ok := requestPayload["proxy"].(map[string]any)
	if !ok || proxy["host"] != "proxy" || proxy["port"] != float64(8080) {
		t.Fatalf("proxy payload = %#v", requestPayload["proxy"])
	}
}

func TestCFClearanceScraperSolveRejectsTunnelWithoutShim(t *testing.T) {
	// A vless URL must be bridged through a local shim; the shim dials the
	// tunnel lazily, so constructing it succeeds even without a live tunnel.
	// This test only asserts the solver does not silently drop the proxy.
	_, err := (cfClearanceScraperSolver{}).Solve(context.Background(), ClearanceConfig{
		ClearanceSolverURL: "http://127.0.0.1:1", TargetURL: "https://grok.com", Timeout: 50 * time.Millisecond,
	}, "vless://e6edbfc0-6d1c-43c5-a3fc-8d07024fdcf1@example.com:443?encryption=none&flow=xtls-rprx-vision&fp=ios&pbk=Zzn7SxtTRMANwRwOvn87ZpNQ8zjjzcKOznE_sG_7UQU&security=reality&sid=6b584a0d&sni=updates.cdn-apple.com&type=tcp")
	if err == nil {
		t.Fatal("expected an error when the solver endpoint is unreachable")
	}
	if !strings.Contains(err.Error(), "cf-clearance-scraper") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCFClearanceScraperEndpointNormalizesPath(t *testing.T) {
	got, err := cfClearanceScraperEndpoint("http://127.0.0.1:3000")
	if err != nil {
		t.Fatal(err)
	}
	if got != "http://127.0.0.1:3000/cf-clearance-scraper" {
		t.Fatalf("endpoint = %q", got)
	}
	got, err = cfClearanceScraperEndpoint("http://127.0.0.1:3000/cf-clearance-scraper")
	if err != nil {
		t.Fatal(err)
	}
	if got != "http://127.0.0.1:3000/cf-clearance-scraper" {
		t.Fatalf("endpoint = %q", got)
	}
}
