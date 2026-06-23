// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright contributors to the prec project.

package nfpm

import (
	"os"
	"strings"
	"testing"
)

func TestPostinstallScriptRestartsPrecdOnUpgrade(t *testing.T) {
	t.Helper()

	// Ensure package upgrade script logic keeps restarting precd on updates.
	data, err := os.ReadFile("precd.postinstall.sh")
	if err != nil {
		t.Fatalf("failed to read postinstall script: %v", err)
	}
	script := string(data)

	if !strings.Contains(script, "is_upgrade=1") {
		t.Fatalf("postinstall script must detect upgrade path")
	}
	if !strings.Contains(script, "$1\" = \"configure\"") {
		t.Fatalf("postinstall script must detect deb upgrade path")
	}
	if !strings.Contains(script, "systemctl restart precd.service") {
		t.Fatalf("postinstall script must restart precd on upgrade")
	}
}
