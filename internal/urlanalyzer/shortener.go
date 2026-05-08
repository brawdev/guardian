package urlanalyzer

import (
	"net/http"
	"strings"
	"time"
)

var knownShorteners = []string{
	"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
	"short.link", "rb.gy", "cutt.ly", "tiny.cc", "is.gd",
	"buff.ly", "ift.tt", "shorturl.at", "tr.im", "snip.ly",
}

func IsShortURL(rawURL string) bool {
	host := extractHost(rawURL)
	for _, s := range knownShorteners {
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}

// ExpandShortURL sigue la redirección de un URL corto y devuelve el destino real.
func ExpandShortURL(rawURL string) (string, bool) {
	client := &http.Client{
		Timeout: 8 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(rawURL)
	if err != nil {
		return rawURL, false
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		if location != "" && location != rawURL {
			return location, true
		}
	}
	return rawURL, false
}
