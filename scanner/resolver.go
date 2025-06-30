package scanner

import (
	"fmt"
	"net"
)

func RunDNSLookups(domain string) map[string][]string {
	results := make(map[string][]string)

	if a, err := net.LookupHost(domain); err == nil {
		results["A"] = a
	}
	if cname, err := net.LookupCNAME(domain); err == nil {
		results["CNAME"] = []string{cname}
	}
	if mx, err := net.LookupMX(domain); err == nil {
		var mxs []string
		for _, m := range mx {
			mxs = append(mxs, fmt.Sprintf("%s (%d)", m.Host, m.Pref))
		}
		results["MX"] = mxs
	}
	if txt, err := net.LookupTXT(domain); err == nil {
		results["TXT"] = txt
	}

	return results
}

func ReverseLookup(domain string) string {
	ips, err := net.LookupIP(domain)
	if err != nil || len(ips) == 0 {
		return "Reverse Lookup Başarısız"
	}

	rev, err := net.LookupAddr(ips[0].String())
	if err != nil || len(rev) == 0 {
		return "PTR kaydı bulunamadı"
	}

	return rev[0]
}
