package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"golang.org/x/mod/modfile"
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
		DatabaseSpecific struct {
			URL string `json:"url"`
		} `json:"database_specific"`
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
	SchemaVersion string `json:"schema_version"`
}

// TODO: Implement the usage of this interface
type Vulnerability struct {
	id           string
	ref          string
	fixedVersion string
}

type Module struct {
	name       string
	version    string
	vulnerable bool

	vulnerabilities []Vulnerability
}

func (m *Module) Parse() {
	response, err := http.Get("https://vuln.go.dev/" + m.name + ".json")

	if err != nil {
		log.Fatal((err))
	}

	if response.Status != "200 OK" {
		if verbose {
			fmt.Println("No Security Entries for " + m.name)
		}
	} else {
		responseData, err := ioutil.ReadAll(response.Body)
		if err != nil {
			log.Fatal(err)
		}

		var responseObject GoVulnResponse
		json.Unmarshal(responseData, &responseObject)

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

					isVulnerable, fixedVersion := isVulnerableBetweenRanges(m.version, vulnRanges)

					if isVulnerable {
						m.vulnerable = true

						m.vulnerabilities = append(m.vulnerabilities, Vulnerability{
							id:           vuln.ID,
							ref:          affected.DatabaseSpecific.URL,
							fixedVersion: fixedVersion,
						})
					}
				}
			}
		}
	}
}

var (
	fileLocation string
	verbose      bool
)

func main() {
	flag.BoolVar(&verbose, "verbose", false, "Enable/Disable verbose output")
	flag.Parse()

	content, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		log.Fatal(err)
	}

	f, err := modfile.Parse("go.mod", content, nil)
	if err != nil {
		panic(err)
	}

	for _, m := range f.Require {
		currentMod := Module{
			name:    m.Mod.Path,
			version: m.Mod.Version,
		}

		currentMod.Parse()

		if currentMod.vulnerable {
			displayModuleAudit(&currentMod)
		}
	}
}
