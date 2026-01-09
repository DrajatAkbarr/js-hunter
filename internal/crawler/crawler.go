package crawler

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/html"
)

var httpClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: nil,
	},
}

func ExtractJSLinks(targetURL string) ([]string, error) {
	parsedTargetURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	resp, err := httpClient.Get(targetURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch target: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("target returned non-200 status: %d", resp.StatusCode)
	}

	doc, err := html.Parse(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTML: %w", err)
	}

	jsLinks := make(map[string]struct{})

	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "script" {
			for _, a := range n.Attr {
				if a.Key == "src" {
					jsURL := strings.TrimSpace(a.Val)
					if jsURL == "" {
						continue
					}

					parsedJS, err := url.Parse(jsURL)
					if err != nil {
						continue
					}
					fullURL := parsedTargetURL.ResolveReference(parsedJS).String()

					if strings.HasSuffix(strings.Split(fullURL, "?")[0], ".js") {
						jsLinks[fullURL] = struct{}{}
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)

	var uniqueLinks []string
	for link := range jsLinks {
		uniqueLinks = append(uniqueLinks, link)
	}

	return uniqueLinks, nil
}

func DownloadFile(url string) ([]byte, error) {
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status not OK: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}
