package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
)

type Project struct {
	Name              string
	GoVersion         string
	VulnerableModules []Module
}

func (p *Project) ToJSON() {
	b, err := json.Marshal(p)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(string(b))
}

func (p *Project) ToXML() {
	b, err := xml.Marshal(p)

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(string(b))
}

func (p *Project) DisplayAudit() {
	for _, module := range p.VulnerableModules {
		displayModuleAuditTable(&module)
	}
}
