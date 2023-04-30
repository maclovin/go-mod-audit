package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

type GoVulnResponse []struct {
	ID        string    `json:"id"`
	Published time.Time `json:"published"`
	Modified  time.Time `json:"modified"`
	Aliases   []string  `json:"aliases"`
	Details   string    `json:"details"`
	Affected  []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced,omitempty"`
				Fixed      string `json:"fixed,omitempty"`
			} `json:"events"`
		} `json:"ranges"`
		EcosystemSpecific struct {
			Imports []struct {
				Path    string   `json:"path"`
				Symbols []string `json:"symbols"`
			} `json:"imports"`
		} `json:"ecosystem_specific"`
	} `json:"affected"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
	Credits []struct {
		Name string `json:"name"`
	} `json:"credits"`
	DatabaseSpecific struct {
		URL string `json:"url"`
	} `json:"database_specific"`
}

type Vulnerability struct {
	ID           string
	Ref          string
	FixedVersion string
}

type Module struct {
	Name       string
	Version    string
	Vulnerable bool

	Vulnerabilities []Vulnerability
}

func (m *Module) Parse() {
	response, err := http.Get("https://vuln.go.dev/" + m.Name + ".json")

	if err != nil {
		log.Fatal((err))
	}

	if response.Status != "200 OK" {
		if verbose {
			fmt.Println("[INFO] No vulnerability entries for", m.Name)
		}
	} else {
		if verbose {
			fmt.Println("[WARN] Analyzing vulnerability entries for", m.Name)
		}
		responseData, err := ioutil.ReadAll(response.Body)
		if err != nil {
			log.Fatal(err)
		}

		var responseObject GoVulnResponse
		json.Unmarshal(responseData, &responseObject)

		fmt.Println(responseObject)

		// I know, shame on me, But I'm just hacking.
		for _, vuln := range responseObject {
			for _, affected := range vuln.Affected {
				for _, ranges := range affected.Ranges {
					var vulnRanges = []string{}

					for _, event := range ranges.Events {
						if event.Introduced != "" {
							vulnRanges = append(vulnRanges, event.Introduced)
						}
						if event.Fixed != "" {
							vulnRanges = append(vulnRanges, event.Fixed)
						}
					}

					isVulnerable, fixedVersion := isVulnerableBetweenRanges(m.Version, vulnRanges)

					if isVulnerable {
						m.Vulnerable = true
						m.Vulnerabilities = append(m.Vulnerabilities, Vulnerability{
							ID:           vuln.ID,
							Ref:          vuln.DatabaseSpecific.URL,
							FixedVersion: fixedVersion,
						})

						if verbose {
							fmt.Println("- Found vulnerability:", vuln.ID)
						}
					}
				}
			}
		}
	}
}
