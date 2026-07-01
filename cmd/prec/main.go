// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright contributors to the prec project.

package main

import (
	"fmt"
	"os"

	"github.com/jfut/prec/internal/cli"
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
