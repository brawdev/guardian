package urlanalyzer

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type ReputationResult struct {
	SafeBrowsing SafeBrowsingResult `json:"safe_browsing,omitempty"`
	VirusTotal   VirusTotalResult   `json:"virus_total,omitempty"`
}

type SafeBrowsingResult struct {
	IsMalicious bool     `json:"is_malicious,omitempty"`
	ThreatTypes []string `json:"threat_types,omitempty"`
	Error       string   `json:"error,omitempty"`
}

type VirusTotalResult struct {
	IsMalicious  bool     `json:"is_malicious,omitempty"`
	Malicious    int      `json:"malicious,omitempty"`
	Suspicious   int      `json:"suspicious,omitempty"`
	TotalEngines int      `json:"total_engines,omitempty"`
	Vendors      []string `json:"vendors,omitempty"`
	Error        string   `json:"error,omitempty"`
}

type sbRequest struct {
	Client    sbClient     `json:"client"`
	ThreatInfo sbThreatInfo `json:"threatInfo"`
}

type sbClient struct {
	ClientID      string `json:"clientId"`
	ClientVersion string `json:"clientVersion"`
}

type sbThreatInfo struct {
	ThreatTypes      []string   `json:"threatTypes"`
	PlatformTypes    []string   `json:"platformTypes"`
	ThreatEntryTypes []string   `json:"threatEntryTypes"`
	ThreatEntries    []sbEntry  `json:"threatEntries"`
}

type sbEntry struct {
	URL string `json:"url"`
}

type sbResponse struct {
	Matches []struct {
		ThreatType string `json:"threatType"`
	} `json:"matches"`
}

func CheckReputation(rawURL, safeBrowsingKey, virusTotalKey string) ReputationResult {
	result := ReputationResult{}

	if safeBrowsingKey != "" {
		result.SafeBrowsing = querySafeBrowsing(rawURL, safeBrowsingKey)
	}
	if virusTotalKey != "" {
		result.VirusTotal = queryVirusTotal(rawURL, virusTotalKey)
	}

	return result
}

func querySafeBrowsing(rawURL, apiKey string) SafeBrowsingResult {
	payload := sbRequest{
		Client: sbClient{ClientID: "my-guardian", ClientVersion: "1.0"},
		ThreatInfo: sbThreatInfo{
			ThreatTypes:      []string{"MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"},
			PlatformTypes:    []string{"ANY_PLATFORM"},
			ThreatEntryTypes: []string{"URL"},
			ThreatEntries:    []sbEntry{{URL: rawURL}},
		},
	}

	body, _ := json.Marshal(payload)
	endpoint := fmt.Sprintf("https://safebrowsing.googleapis.com/v4/threatMatches:find?key=%s", apiKey)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(endpoint, "application/json", bytes.NewReader(body))
	if err != nil {
		return SafeBrowsingResult{Error: err.Error()}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return SafeBrowsingResult{Error: fmt.Sprintf("Safe Browsing API status: %d", resp.StatusCode)}
	}

	var sbResp sbResponse
	if err := json.NewDecoder(resp.Body).Decode(&sbResp); err != nil {
		return SafeBrowsingResult{Error: err.Error()}
	}

	result := SafeBrowsingResult{IsMalicious: len(sbResp.Matches) > 0}
	for _, m := range sbResp.Matches {
		result.ThreatTypes = append(result.ThreatTypes, m.ThreatType)
	}
	return result
}

func queryVirusTotal(rawURL, apiKey string) VirusTotalResult {
	// VirusTotal v3: el ID de un URL es base64url sin padding
	id := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString([]byte(rawURL))

	endpoint := "https://www.virustotal.com/api/v3/urls/" + id
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return VirusTotalResult{Error: err.Error()}
	}
	req.Header.Set("x-apikey", apiKey)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return VirusTotalResult{Error: err.Error()}
	}
	defer resp.Body.Close()

	// 404 = URL nunca escaneada — no es un error, simplemente no hay datos
	if resp.StatusCode == http.StatusNotFound {
		return VirusTotalResult{Error: "sin datos previos en VirusTotal"}
	}
	if resp.StatusCode != http.StatusOK {
		return VirusTotalResult{Error: fmt.Sprintf("VirusTotal API status: %d", resp.StatusCode)}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return VirusTotalResult{Error: err.Error()}
	}

	var vtResp struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats struct {
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
					Harmless   int `json:"harmless"`
					Undetected int `json:"undetected"`
				} `json:"last_analysis_stats"`
				LastAnalysisResults map[string]struct {
					Category string `json:"category"`
				} `json:"last_analysis_results"`
			} `json:"attributes"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &vtResp); err != nil {
		return VirusTotalResult{Error: err.Error()}
	}

	stats := vtResp.Data.Attributes.LastAnalysisStats
	total := stats.Malicious + stats.Suspicious + stats.Harmless + stats.Undetected

	result := VirusTotalResult{
		Malicious:    stats.Malicious,
		Suspicious:   stats.Suspicious,
		TotalEngines: total,
		IsMalicious:  stats.Malicious >= 2,
	}

	for vendor, detail := range vtResp.Data.Attributes.LastAnalysisResults {
		if detail.Category == "malicious" || detail.Category == "suspicious" {
			result.Vendors = append(result.Vendors, vendor)
		}
	}

	return result
}

func VTVendorSummary(vendors []string) string {
	if len(vendors) == 0 {
		return ""
	}
	if len(vendors) <= 3 {
		return strings.Join(vendors, ", ")
	}
	return strings.Join(vendors[:3], ", ") + fmt.Sprintf(" y %d más", len(vendors)-3)
}
