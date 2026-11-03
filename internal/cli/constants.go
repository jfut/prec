// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright contributors to the prec project.

package cli

import "time"

const treeLinkWindow = 300 * time.Millisecond
const followPollInterval = 300 * time.Millisecond

// maxLogLineLength bounds memory used to read a single record from an input log.
const maxLogLineLength = 16 * 1024 * 1024

const (
	logCompressionNone = "none"
	logCompressionGzip = "gz"
	logCompressionZstd = "zstd"

	outputFormatText = "text"
	outputFormatJSON = "json"
	outputFormatCSV  = "csv"

	// Keep help output readable while allowing a wider modern terminal baseline.
	helpWrapUpperBound = 90
)

const commandEndRecordTypeMarker = `"record_type":"proc_end"`

var gzipFrameMagic = []byte{0x1f, 0x8b, 0x08}
var zstdFrameMagic = []byte{0x28, 0xb5, 0x2f, 0xfd}
