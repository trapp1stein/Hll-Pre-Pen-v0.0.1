package owasp

import (
	"fmt"
	"net/http"
	"strings"
	_"crypto/tls"
	_"io"
)

type Finding struct {
	Category string
	Severity string
	Summary  string
	Detail   string
}

var Findings []Finding

func Analyze(target string) []Finding {
	Findings = []Finding{} // temizle

	if !strings.HasPrefix(target, "http") {
		target = "http://" + target
	}

	resp, err := http.Get(target)
	if err != nil {
		Findings = append(Findings, Finding{
			Category: "A06: Security Misconfiguration",
			Severity: "High",
			Summary:  "Site erişilemedi",
			Detail:   fmt.Sprintf("%v", err),
		})
		return Findings
	}
	defer resp.Body.Close()

	testHeaders(resp)
	testSSL(target)
	testInjection(target)
	testAuth(target)

	return Findings
}

func testHeaders(resp *http.Response) {
	required := []string{"X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy"}
	for _, h := range required {
		if _, ok := resp.Header[h]; !ok {
			Findings = append(Findings, Finding{
				Category: "A05: Security Misconfiguration",
				Severity: "Medium",
				Summary:  fmt.Sprintf("Eksik HTTP Header: %s", h),
				Detail:   "Güvenlik başlığı eksik, clickjacking veya MIME tipi hataları oluşabilir.",
			})
		}
	}
}
