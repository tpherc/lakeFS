package httputil

import (
	"net/url"
	"path"
	"strings"
	"unicode"
)

// SafeRelativeRedirect returns a local redirect target or an empty string.
// It rejects absolute URLs, protocol-relative URLs, control characters,
// backslashes, and caller-provided loop targets.
func SafeRelativeRedirect(raw string, blockedPaths ...string) string {
	target := strings.TrimSpace(raw)
	if target == "" || strings.IndexFunc(target, unicode.IsControl) >= 0 {
		return ""
	}
	u, err := url.Parse(target)
	if err != nil || u.IsAbs() || u.Host != "" || u.User != nil || u.Opaque != "" {
		return ""
	}
	decodedPath, err := fullyUnescapePath(u.EscapedPath())
	if err != nil ||
		strings.IndexFunc(decodedPath, unicode.IsControl) >= 0 ||
		strings.Contains(decodedPath, "\\") ||
		!strings.HasPrefix(decodedPath, "/") ||
		strings.HasPrefix(decodedPath, "//") {
		return ""
	}
	cleanPath := path.Clean(decodedPath)
	for _, blocked := range blockedPaths {
		if cleanPath == blocked {
			return ""
		}
	}
	return u.String()
}

func fullyUnescapePath(escapedPath string) (string, error) {
	decodedPath := escapedPath
	for range 2 {
		next, err := url.PathUnescape(decodedPath)
		if err != nil {
			return "", err
		}
		if next == decodedPath {
			return decodedPath, nil
		}
		decodedPath = next
	}
	return decodedPath, nil
}
