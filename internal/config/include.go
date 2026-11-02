// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright contributors to the prec project.

package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// loadConfig applies a file, then its includes, preserving rule order across files.
func loadConfig(path string, data []byte, cfg *Config, parents []os.FileInfo) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, fmt.Errorf("stat config %q: %w", path, err)
	}
	for _, parent := range parents {
		// Compare file identities to detect cycles through symlinks and hard links too.
		if os.SameFile(info, parent) {
			return false, fmt.Errorf("include cycle in config %q", path)
		}
	}
	parents = append(parents, info)

	file := struct {
		Config
		Include string `toml:"include"`
	}{Config: *cfg}
	// Decode rules separately so each file appends to the accumulated lists.
	file.Filter = nil
	file.CaptureFilter = nil
	meta, err := toml.Decode(string(data), &file)
	if err != nil {
		return false, fmt.Errorf("parse config %q: %w", path, err)
	}
	if err := validateLegacyFilterKeys(meta); err != nil {
		return false, fmt.Errorf("config %q: %w", path, err)
	}
	file.Filter = append(cfg.Filter, file.Filter...)
	file.CaptureFilter = append(cfg.CaptureFilter, file.CaptureFilter...)
	*cfg = file.Config
	compressLevelDefined := meta.IsDefined("compress_level")
	if file.Include == "" {
		return compressLevelDefined, nil
	}

	pattern := file.Include
	if !filepath.IsAbs(pattern) {
		pattern = filepath.Join(filepath.Dir(path), pattern)
	}
	// Glob returns matches in lexical order and permits an empty drop-in directory.
	paths, err := filepath.Glob(pattern)
	if err != nil {
		return false, fmt.Errorf("include in config %q: %w", path, err)
	}
	for _, includedPath := range paths {
		data, err := os.ReadFile(includedPath)
		if err != nil {
			return false, fmt.Errorf("read included config %q: %w", includedPath, err)
		}
		defined, err := loadConfig(includedPath, data, cfg, parents)
		if err != nil {
			return false, err
		}
		compressLevelDefined = compressLevelDefined || defined
	}
	return compressLevelDefined, nil
}
