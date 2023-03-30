package main

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/rodaine/table"
)

var (
	headerFmt      = color.New(color.FgHiGreen, color.Bold).SprintfFunc()
	brightFmt      = color.New(color.FgHiWhite, color.Bold).SprintFunc()
	vulnModFmt     = color.New(color.FgHiRed, color.Bold).SprintfFunc()
	tableHeaderFmt = color.New(color.FgHiWhite, color.Underline, color.Bold).SprintfFunc()
)

func displayHeader(project *Project) {
	fmt.Println(brightFmt("\nAudit Report for " + project.Name + " (Go v" + project.GoVersion + ")\n"))
}

func displayModuleAuditTable(module *Module) {
	fmt.Print("\n")
	fmt.Println(vulnModFmt(module.Name + " (" + module.Version + ")\n"))

	tbl := table.New("Vuln ID", "Fixed Version", "Ref")
	tbl.WithHeaderFormatter(tableHeaderFmt)

	for _, v := range module.Vulnerabilities {
		tbl.AddRow(v.ID, v.FixedVersion, v.Ref)
	}

	tbl.Print()
	fmt.Print("\n")
}
