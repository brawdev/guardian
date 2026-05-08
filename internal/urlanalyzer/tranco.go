package urlanalyzer

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type TrancoResult struct {
	Rank      int    `json:"rank,omitempty"`
	InTopList bool   `json:"in_top_list,omitempty"`
	Error     string `json:"error,omitempty"`
}

func CheckTrancoRank(hostname string) TrancoResult {
	domain := extractRootDomain(hostname)

	ch := make(chan TrancoResult, 1)
	go func() {
		client := &http.Client{Timeout: 6 * time.Second}
		url := fmt.Sprintf("https://tranco-list.eu/api/ranks/domain/%s", domain)
		resp, err := client.Get(url)
		if err != nil {
			ch <- TrancoResult{Error: err.Error()}
			return
		}
		defer resp.Body.Close()

		var data struct {
			Ranks []struct {
				Rank int `json:"rank"`
			} `json:"ranks"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			ch <- TrancoResult{Error: err.Error()}
			return
		}

		if len(data.Ranks) == 0 {
			ch <- TrancoResult{InTopList: false}
			return
		}
		ch <- TrancoResult{InTopList: true, Rank: data.Ranks[0].Rank}
	}()

	select {
	case <-time.After(7 * time.Second):
		return TrancoResult{Error: "timeout en consulta Tranco"}
	case res := <-ch:
		return res
	}
}
