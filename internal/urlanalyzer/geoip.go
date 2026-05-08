package urlanalyzer

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

type GeoIPResult struct {
	IP          string `json:"ip,omitempty"`
	Country     string `json:"country,omitempty"`
	CountryCode string `json:"country_code,omitempty"`
	City        string `json:"city,omitempty"`
	ISP         string `json:"isp,omitempty"`
	IsHosting   bool   `json:"is_hosting,omitempty"`
	Error       string `json:"error,omitempty"`
}

// highRiskCountries países frecuentemente asociados a infraestructura de phishing
var highRiskCountries = []string{"RU", "CN", "NG", "UA", "KP", "RO", "BG"}

func CheckGeoIP(hostname string) GeoIPResult {
	ch := make(chan GeoIPResult, 1)
	go func() {
		ips, err := net.LookupHost(hostname)
		if err != nil || len(ips) == 0 {
			ch <- GeoIPResult{Error: "no se pudo resolver la IP del dominio"}
			return
		}
		ip := ips[0]

		client := &http.Client{Timeout: 6 * time.Second}
		url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,country,countryCode,city,isp,hosting", ip)
		resp, err := client.Get(url)
		if err != nil {
			ch <- GeoIPResult{IP: ip, Error: err.Error()}
			return
		}
		defer resp.Body.Close()

		var data struct {
			Status      string `json:"status"`
			Country     string `json:"country"`
			CountryCode string `json:"countryCode"`
			City        string `json:"city"`
			ISP         string `json:"isp"`
			Hosting     bool   `json:"hosting"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			ch <- GeoIPResult{IP: ip, Error: err.Error()}
			return
		}

		ch <- GeoIPResult{
			IP:          ip,
			Country:     data.Country,
			CountryCode: data.CountryCode,
			City:        data.City,
			ISP:         data.ISP,
			IsHosting:   data.Hosting,
		}
	}()

	select {
	case <-time.After(7 * time.Second):
		return GeoIPResult{Error: "timeout en consulta GeoIP"}
	case res := <-ch:
		return res
	}
}

func isHighRiskCountry(countryCode string) bool {
	code := strings.ToUpper(countryCode)
	for _, c := range highRiskCountries {
		if code == c {
			return true
		}
	}
	return false
}
