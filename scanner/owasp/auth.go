package owasp

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var commonCredentials = []struct {
	Username string
	Password string
}{
	{"admin", "admin"},
	{"admin", "password"},
	{"user", "user"},
	{"test", "test"},
}

func testAuth(target string) {
	loginURL := findLoginURL(target)
	if loginURL == "" {
		// Login URL bulunamadı
		return
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	for _, cred := range commonCredentials {
		form := fmt.Sprintf("username=%s&password=%s", cred.Username, cred.Password)
		req, err := http.NewRequest("POST", loginURL, bytes.NewBufferString(form))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		bodyBytes, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		body := strings.ToLower(string(bodyBytes))

		if resp.StatusCode == 200 && !strings.Contains(body, "invalid") && !strings.Contains(body, "error") {
			Findings = append(Findings, Finding{
				Category: "A07: Identification and Authentication Failures",
				Severity: "High",
				Summary:  "Basit kimlik doğrulama bypass testi başarılı",
				Detail:   fmt.Sprintf("Başarılı login tespit edildi: %s / %s", cred.Username, cred.Password),
			})
			break
		}
	}
}

func findLoginURL(target string) string {
	if !strings.HasPrefix(target, "http") {
		target = "http://" + target
	}

	candidates := []string{
		"/login",
		"/admin/login",
		"/user/login",
		"/signin",
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	for _, path := range candidates {
		url := strings.TrimRight(target, "/") + path
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == 200 {
			return url
		}
	}
	return ""
}
