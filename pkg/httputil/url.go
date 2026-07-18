package httputil

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

func RequestBaseURL(r *http.Request) (string, error) {
	host := r.Host
	if host == "" {
		return "", fmt.Errorf("missing request host")
	}
	return NormalizeBaseURL(RequestScheme(r) + "://" + host)
}

func NormalizeBaseURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("base URL scheme must be http or https")
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("base URL must include a host")
	}
	if parsed.User != nil {
		return "", fmt.Errorf("base URL must not include user info")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("base URL must not include query or fragment")
	}
	parsed.Host = strings.ToLower(parsed.Host)
	return strings.TrimRight(parsed.String(), "/"), nil
}

func BaseURLUsesHTTPS(raw string) (bool, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false, err
	}
	return strings.EqualFold(parsed.Scheme, "https"), nil
}

func BaseURLUsesLoopbackHTTP(raw string) (bool, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false, err
	}
	if !strings.EqualFold(parsed.Scheme, "http") {
		return false, nil
	}
	host := parsed.Hostname()
	if strings.EqualFold(host, "localhost") {
		return true, nil
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback(), nil
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.IsLoopback(), nil
	}
	return false, nil
}
