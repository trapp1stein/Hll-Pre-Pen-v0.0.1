package owasp

import (
	"crypto/tls"
	"fmt"
	"strings"
)

func testSSL(target string) {
	if !strings.HasPrefix(target, "https") {
		Findings = append(Findings, Finding{
			Category: "A02: Cryptographic Failures",
			Severity: "High",
			Summary:  "HTTPS kullanılmıyor",
			Detail:   "Site güvenli değil. HTTPS yerine HTTP kullanılıyor.",
		})
		return
	}

	host := strings.Split(strings.TrimPrefix(target, "https://"), "/")[0]
	conn, err := tls.Dial("tcp", host+":443", &tls.Config{})
	if err != nil {
		Findings = append(Findings, Finding{
			Category: "A02: Cryptographic Failures",
			Severity: "High",
			Summary:  "TLS bağlantısı başarısız",
			Detail:   fmt.Sprintf("%v", err),
		})
		return
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		Findings = append(Findings, Finding{
			Category: "A02: Cryptographic Failures",
			Severity: "Medium",
			Summary:  "Sertifika bilgisi alınamadı",
			Detail:   "TLS sertifikası eksik veya geçersiz.",
		})
	}
}
