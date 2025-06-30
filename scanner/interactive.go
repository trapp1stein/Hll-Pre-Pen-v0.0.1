package scanner

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"hllprepen/scanner/owasp"

)

type ScanInfo struct {
	EventName string
	TargetURL string
	TestType  string // Black, Grey, White
	Time      time.Time
}

type ReportData struct {
	ScanInfo
	DNSRecords    map[string][]string
	Reverse       string
	WhoisSummary  string
	OwaspFindings []owasp.Finding
}

var currentInfo ScanInfo
func Init() {}

func StartInteractiveSession() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Olay Adı: ")
	event, _ := reader.ReadString('\n')

	fmt.Print("Hedef Domain/IP: ")
	target, _ := reader.ReadString('\n')

	fmt.Println("Test Türü Seçin:")
	fmt.Println("[1] Black Box (OSINT - OWASP 10)")
	fmt.Print("Seçiminiz: ")
	typeChoice, _ := reader.ReadString('\n')

	testTypeMap := map[string]string{"1": "Black Box (OSINT - OWASP 10)", "2": "Grey", "3": "White", "4": "Hepsi"}
	testType := testTypeMap[strings.TrimSpace(typeChoice)]

	currentInfo = ScanInfo{
		EventName: strings.TrimSpace(event),
		TargetURL: strings.TrimSpace(target),
		TestType:  testType,
		Time:      time.Now(),
	}

	fmt.Println("\nTest başlatılıyor...")

	ResolveAndReport(currentInfo)
}

// ResolveAndReport fonksiyonu diğer testleri yapar ve rapor oluşturur.
func ResolveAndReport(info ScanInfo) {
	report := ReportData{ScanInfo: info}

	fmt.Println("DNS kayıtları alınıyor...")
	report.DNSRecords = RunDNSLookups(info.TargetURL)

	fmt.Println("Reverse lookup yapılıyor...")
	report.Reverse = ReverseLookup(info.TargetURL)

	fmt.Println("WHOIS sorgulanıyor...")
	report.WhoisSummary = RunWhois(info.TargetURL)

	fmt.Println("OWASP Top 10 analizleri başlatılıyor...")
	report.OwaspFindings = owasp.Analyze(info.TargetURL)

	fmt.Println("PDF raporu oluşturuluyor...")
	GeneratePDF(report)

	fmt.Println("\nTest tamamlandı!")
}
