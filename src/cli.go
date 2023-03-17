package main

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/rodaine/table"
)

var (
	vulnModFmt     = color.New(color.FgHiRed, color.Bold).SprintfFunc()
	tableHeaderFmt = color.New(color.FgHiWhite, color.Underline, color.Bold).SprintfFunc()
)

func displayModuleAudit(module *Module) {
	fmt.Println(vulnModFmt(module.name + " (" + module.version + ")\n"))

	tbl := table.New("Vuln ID", "Fixed Version", "Ref")
	tbl.WithHeaderFormatter(tableHeaderFmt)

	for _, v := range module.vulnerabilities {
		tbl.AddRow(v.id, v.fixedVersion, v.ref)
	}

	tbl.Print()
	fmt.Print("\n\n")
}
