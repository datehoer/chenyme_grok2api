package egress

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	application "github.com/chenyme/grok2api/backend/internal/application/egress"
)

const maxCFClearanceScraperResponseBytes = 2 << 20

// cfClearanceScraperSolver 通过本地部署的 cf-clearance-scraper 服务求解
// Cloudflare WAF 会话，产出绑定出口 IP 的 CF cookie 与浏览器 User-Agent。
// 与 FlareSolverr 不同，它支持通过本地 HTTP CONNECT shim 走 vless/trojan 等
// 隧道代理，从而让 clearance 绑定在网关实际使用的出口 IP 上。
type cfClearanceScraperSolver struct{}

func (cfClearanceScraperSolver) Solve(ctx context.Context, cfg ClearanceConfig, proxyURL string) (clearanceSolution, error) {
	endpoint, err := cfClearanceScraperEndpoint(cfg.ClearanceSolverURL)
	if err != nil {
		return clearanceSolution{}, err
	}
	target := strings.TrimSpace(cfg.TargetURL)
	if target == "" {
		target = "https://grok.com"
	}
	browserProxy, err := resolveBrowserProxy(proxyURL, "")
	if err != nil {
		return clearanceSolution{}, err
	}
	if browserProxy.closeFn != nil {
		defer browserProxy.closeFn()
	}

	payload := map[string]any{
		"mode": "waf-session",
		"url":  target,
	}
	if browserProxy.host != "" {
		proxy := map[string]any{
			"host": browserProxy.host,
			"port": browserProxy.port,
		}
		if browserProxy.username != "" {
			proxy["username"] = browserProxy.username
			proxy["password"] = browserProxy.password
		}
		payload["proxy"] = proxy
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return clearanceSolution{}, fmt.Errorf("编码 cf-clearance-scraper 请求: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return clearanceSolution{}, fmt.Errorf("创建 cf-clearance-scraper 请求: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	if key := strings.TrimSpace(cfg.ClearanceSolverKey); key != "" {
		request.Header.Set("x-client-key", key)
	}
	client := &http.Client{Timeout: cfg.Timeout + 15*time.Second}
	response, err := client.Do(request)
	if err != nil {
		return clearanceSolution{}, fmt.Errorf("调用 cf-clearance-scraper: %w", err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxCFClearanceScraperResponseBytes+1))
	if err != nil {
		return clearanceSolution{}, fmt.Errorf("读取 cf-clearance-scraper 响应: %w", err)
	}
	if len(responseBody) > maxCFClearanceScraperResponseBytes {
		return clearanceSolution{}, fmt.Errorf("cf-clearance-scraper 响应过大")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return clearanceSolution{}, fmt.Errorf("cf-clearance-scraper 返回 HTTP %d", response.StatusCode)
	}
	var result struct {
		Code    int `json:"code"`
		Cookies []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"cookies"`
		Headers map[string]string `json:"headers"`
	}
	if err := json.Unmarshal(responseBody, &result); err != nil {
		return clearanceSolution{}, fmt.Errorf("解析 cf-clearance-scraper 响应: %w", err)
	}
	if result.Code != 0 && result.Code != 200 {
		return clearanceSolution{}, fmt.Errorf("cf-clearance-scraper 求解失败: code %d", result.Code)
	}
	parts := make([]string, 0, len(result.Cookies))
	for _, cookie := range result.Cookies {
		if strings.TrimSpace(cookie.Name) != "" && strings.TrimSpace(cookie.Value) != "" {
			parts = append(parts, cookie.Name+"="+cookie.Value)
		}
	}
	cookies := application.SanitizeCloudflareCookies(strings.Join(parts, "; "))
	userAgent := strings.TrimSpace(result.Headers["user-agent"])
	if userAgent == "" {
		userAgent = strings.TrimSpace(result.Headers["User-Agent"])
	}
	if userAgent == "" || len(userAgent) > 512 || strings.IndexFunc(userAgent, func(character rune) bool { return character < 0x20 || character == 0x7f }) >= 0 {
		return clearanceSolution{}, fmt.Errorf("cf-clearance-scraper 返回的 User-Agent 无效")
	}
	return clearanceSolution{Cookies: cookies, UserAgent: userAgent}, nil
}

func cfClearanceScraperEndpoint(value string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Host == "" || parsed.User != nil {
		return "", fmt.Errorf("cf-clearance-scraper URL 无效")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("cf-clearance-scraper URL 必须使用 HTTP 或 HTTPS")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("cf-clearance-scraper URL 不能包含查询参数或片段")
	}
	path := strings.TrimSuffix(parsed.EscapedPath(), "/")
	if path == "" {
		path = "/cf-clearance-scraper"
	} else if path != "/cf-clearance-scraper" {
		path += "/cf-clearance-scraper"
	}
	parsed.RawPath = ""
	parsed.Path = path
	return parsed.String(), nil
}
