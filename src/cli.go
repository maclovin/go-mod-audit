package main

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/rodaine/table"
)

var (
	clearFmt       = color.New(color.FgHiGreen, color.Bold).SprintfFunc()
	brightFmt      = color.New(color.FgHiWhite, color.Bold).SprintFunc()
	vulnModFmt     = color.New(color.FgHiRed, color.Bold).SprintfFunc()
	tableHeaderFmt = color.New(color.FgHiWhite, color.Underline, color.Bold).SprintfFunc()
)

func displayHeader(project *Project) {
	fmt.Println(brightFmt("\nAudit Report for " + project.Name + " (Go v" + project.GoVersion + ")\n"))
}

func displayClear() {
	fmt.Println(clearFmt("Not vulnerabilities was found!\n"))
}

func displayModuleAuditTable(module *Module) {
	fmt.Print("\n")

	indirect := ""

	if module.Indirect {
		indirect = "(Indirect)"
	}

	fmt.Println(vulnModFmt(module.Name + " " + module.Version + " " + indirect + "\n"))

	tbl := table.New("Vuln ID", "Fixed Version", "Ref")
	tbl.WithHeaderFormatter(tableHeaderFmt)

	for _, vuln := range module.Vulnerabilities {
		tbl.AddRow(vuln.ID, vuln.FixedVersion, vuln.Ref)
	}

	tbl.Print()
	fmt.Print("\n")
}
