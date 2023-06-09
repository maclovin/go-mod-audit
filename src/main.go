package main

import (
	"flag"
	"os"
	"sync"

	"golang.org/x/mod/modfile"
)

var (
	verbose      bool
	toJSON       bool
	toXML        bool
	fileLocation string
)

func main() {
	flag.BoolVar(&verbose, "verbose", false, "Turn on the verbose mode.")
	flag.BoolVar(&toJSON, "toJSON", false, "Output audit results as JSON file.")
	flag.BoolVar(&toXML, "toXML", false, "Output audit results as XML file.")
	flag.StringVar(&fileLocation, "file", "./go.mod", "Path for go.mod file")
	flag.Parse()

	modFileContent, err := os.ReadFile(fileLocation)
	if err != nil {
		panic(err)
	}

	f, err := modfile.Parse("go.mod", modFileContent, nil)
	if err != nil {
		panic(err)
	}

	p := &Project{
		Name:              f.Module.Mod.Path,
		GoVersion:         f.Go.Version,
		VulnerableModules: []Module{},
	}

	var wg sync.WaitGroup

	for _, m := range f.Require {
		wg.Add(1)

		currentMod := &Module{
			Name:     m.Mod.Path,
			Version:  m.Mod.Version,
			Indirect: m.Indirect,
		}

		go func() {
			defer wg.Done()
			currentMod.Parse()

			if currentMod.Vulnerable {
				p.VulnerableModules = append(p.VulnerableModules, *currentMod)
			}
		}()

	}

	wg.Wait()

	if !toJSON && !toXML {
		displayHeader(p)
	}

	if toJSON {
		p.ToJSON()

		return
	}

	if toXML {
		p.ToXML()

		return
	}

	p.DisplayAudit()
}
