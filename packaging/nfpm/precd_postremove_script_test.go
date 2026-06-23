// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright contributors to the prec project.

package nfpm

import (
	"os"
	"strings"
	"testing"
)

func TestPostremoveScriptStopsPrecdOnUninstall(t *testing.T) {
	t.Helper()

	// Ensure uninstall paths stop precd for both rpm and deb packages.
	data, err := os.ReadFile("precd.postremove.sh")
	if err != nil {
		t.Fatalf("failed to read postremove script: %v", err)
	}
	script := string(data)

	if !strings.Contains(script, "remove|purge") {
		t.Fatalf("postremove script must detect deb uninstall path")
	}
	if !strings.Contains(script, "\"$1\" -eq 0") {
		t.Fatalf("postremove script must detect rpm uninstall path")
	}
	if !strings.Contains(script, "systemctl stop precd.service") {
		t.Fatalf("postremove script must stop precd on uninstall")
	}
}
