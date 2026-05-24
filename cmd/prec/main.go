package main

import (
	"fmt"
	"os"

	"github.com/jfut/prec/pkg/cli"
)

// Build metadata fields are injected by linker flags at build time.
var (
	version = "dev"
	commit  = "none"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], formatVersionInfo()))
}

// formatVersionInfo builds a single-line version string for --version output.
func formatVersionInfo() string {
	return fmt.Sprintf(
		"prec %s (%s)",
		version,
		commit,
	)
}
