run:
	go run src/main.go src/cli.go src/module.go src/project.go src/utils.go

build:
	go build -o bin/go-mod-audit src/main.go src/cli.go src/module.go src/project.go src/utils.go