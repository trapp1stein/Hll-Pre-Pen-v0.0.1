package owasp

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

func testInjection(target string) {
	testURL := target
	if strings.Contains(target, "?") {
		testURL += "'"
	} else {
		testURL += "?id=1'"
	}

	resp, err := http.Get(testURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	hints := []string{"sql", "syntax", "mysql", "query", "psql", "error in your"}
	content := strings.ToLower(string(body))
	for _, hint := range hints {
		if strings.Contains(content, hint) {
			Findings = append(Findings, Finding{
				Category: "A03: Injection",
				Severity: "High",
				Summary:  "Muhtemel SQL Injection açığı",
				Detail:   fmt.Sprintf("Yanıtta '%s' ifadesi bulundu.", hint),
			})
			break
		}
	}
}
