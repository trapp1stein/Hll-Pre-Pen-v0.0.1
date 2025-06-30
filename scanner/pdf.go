package scanner

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"path/filepath"
	"strings"
	"time"

	"github.com/jung-kurt/gofpdf"
)

// Türkçe karakterleri ASCII karşılıklarına dönüştürür
func turkishToAscii(str string) string {
	replacer := strings.NewReplacer(
		"ç", "c",
		"Ç", "C",
		"ğ", "g",
		"Ğ", "G",
		"ı", "i",
		"İ", "I",
		"ö", "o",
		"Ö", "O",
		"ş", "s",
		"Ş", "S",
		"ü", "u",
		"Ü", "U",
	)
	return replacer.Replace(str)
}
func normalizeDomain(raw string) string {
	parsed, err := url.Parse(raw)
	if err == nil && parsed.Host != "" {
		raw = parsed.Host
	}
	raw = strings.ToLower(raw)
	raw = strings.Split(raw, "/")[0]              
	raw = strings.Split(raw, ":")[0]              
	raw = regexp.MustCompile(`[^\w.-]`).ReplaceAllString(raw, "") 
	raw = strings.ReplaceAll(raw, ".", "-") // . -> -
	return raw
}
func generateUniqueFilename(base string) string {
	filename := base
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)
	i := 1

	for {
		if _, err := os.Stat(filename); os.IsNotExist(err) {
			break
		}
		filename = fmt.Sprintf("%s-%d%s", name, i, ext)
		i++
	}

	return filename
}

func GeneratePDF(data ReportData) {
	normalized := normalizeDomain(data.TargetURL) // Generate filename from full_url
	baseFilename := fmt.Sprintf("%s-Auto-Pre-Pen-%s.pdf", normalized, time.Now().Format("02-01-06"))
	filename := generateUniqueFilename(baseFilename)
	
	pdf := gofpdf.New("P", "mm", "A4", "")

	pdf.SetMargins(24, 19, 24) // sol: 25mm, üst: 20mm, sağ: 25mm
	pdf.AddPage()

	pdf.SetFont("Arial", "B", 9)
	pdf.Cell(40, 20, turkishToAscii("Auto Pre-Pen Tester (hsky v.1.1.4b)(*4.7-fpm)"))
	pdf.Ln(10)
	pdf.SetFont("Arial", "B", 9)
	pdf.Cell(40, 10, turkishToAscii("Ek Bilgi: "))
	pdf.Ln(8)
	pdf.SetFont("Arial", "", 9)
	text := "-Black (Test edene hiçbir bilgi verilmez.), Gray (Kısmi bilgi sağlanır örn. kullanıcı hesabı), White (Tüm sistem ve kod erişimi sağlanır.)."
	text = turkishToAscii(text)
	pdf.MultiCell(0, 5, text, "", "", false)

	pdf.SetFont("Arial", "", 8)
	pdf.Cell(40, 10, turkishToAscii(fmt.Sprintf("Tanım: %s / Hedef Url: %s / Test: %s / Tarih: %s", data.EventName, data.TargetURL, data.TestType, data.Time.Format("02.01.2006 15:04:05"))))
	pdf.Ln(8)
	pdf.SetFont("Arial", "B", 9)
	pdf.Cell(40, 10, turkishToAscii("Black Box Steps (OSINT)"))
	pdf.Ln(8)
	pdf.SetFont("Arial", "", 9)
	for k, v := range data.DNSRecords {
		pdf.Cell(40, 10, turkishToAscii(fmt.Sprintf("%s: %s", k, strings.Join(v, ", "))))
		pdf.Ln(8)
	}

	pdf.Ln(10)
	pdf.SetFont("Arial", "B", 10)
	pdf.Cell(40, 10, turkishToAscii("Reverse Lookup:"))
	pdf.Ln(8)
	pdf.SetFont("Arial", "", 9)
	pdf.MultiCell(190, 10, turkishToAscii(data.Reverse), "", "L", false)

	pdf.Ln(10)
	pdf.SetFont("Arial", "B", 10)
	pdf.Cell(40, 10, turkishToAscii("WHOIS Özeti:"))
	pdf.Ln(8)
	pdf.SetFont("Arial", "", 9)
	pdf.MultiCell(190, 8, turkishToAscii(data.WhoisSummary), "", "L", false)

	
	pdf.AddPage()
	pdf.Ln(15)
	pdf.SetFont("Arial", "B", 10)
	pdf.Cell(40, 20, turkishToAscii("Auto Pre-Pen Tester (hsky v.1.1.4b)(*4.7-fpm)"))

	pdf.Ln(10)
	pdf.SetFont("Arial", "B", 10)
	pdf.Cell(40, 10, turkishToAscii("OWASP Top 10 Bulguları:"))
	pdf.Ln(8)
	pdf.SetFont("Arial", "", 9)
	if len(data.OwaspFindings) == 0 {
		pdf.Cell(40, 10, turkishToAscii("Bulgular bulunamadı."))
	} else {
		for _, f := range data.OwaspFindings {
			pdf.MultiCell(190, 8, turkishToAscii(fmt.Sprintf("- [%s] %s: %s\nDetay: %s\n", f.Severity, f.Category, f.Summary, f.Detail)), "", "L", false)
			pdf.Ln(4)
		}
	}

	err := pdf.OutputFileAndClose(filename)
	if err != nil {
		fmt.Println("Dosya oluşturulamadı:", err)
	} else {
		fmt.Println("\n Dosya oluşturuldu:", filename)
	}
}
