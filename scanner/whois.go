package scanner

import (
	"os/exec"
	"strings"
)

func RunWhois(target string) string {
	out, err := exec.Command("whois", target).Output()
	if err != nil {
		return "WHOIS sorgusu başarısız"
	}
	lines := strings.Split(string(out), "\n")
	var summary []string

	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "org") ||
			strings.Contains(lower, "owner") ||
			strings.Contains(lower, "country") ||
			strings.Contains(lower, "address") {
			summary = append(summary, line)
		}
	}

	if len(summary) == 0 {
		return "Temel WHOIS bilgisi bulunamadı."
	}
	return strings.Join(summary, "\n")
}
