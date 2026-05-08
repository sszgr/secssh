package main

import (
	"os"

	"github.com/sszgr/secssh/cli"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildTime = "unknown"
)

func main() {
	cli.SetBuildInfo(version, commit, buildTime)
	os.Exit(cli.Run(os.Args[1:]))
}
