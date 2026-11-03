// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright contributors to the prec project.

package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

const (
	DefaultConfigPath = "/etc/prec/precd.conf"
	DefaultLogPath    = "/var/log/prec/prec.log"
	CompressNo        = "no"
	CompressGzip      = "gz"
	CompressZstd      = "zstd"

	LostSamplesActionLog    = "log"
	LostSamplesActionIgnore = "ignore"
	LostSamplesActionStop   = "stop"

	// If not specified, gzip uses the library default and zstd uses level 3.
	DefaultGzipCompressLevel = -1
	DefaultZstdCompressLevel = 3

	// Refresh named capture rules hourly to follow account changes during collection.
	DefaultCaptureFilterRefreshSec = 3600
)

// Config stores daemon runtime settings.
type Config struct {
	LogPath                 string   `toml:"log_path"`
	Compress                string   `toml:"compress"`
	CompressLevel           int      `toml:"compress_level"`
	CollectFileOpen         bool     `toml:"collect_file_open"`
	CollectFileSave         bool     `toml:"collect_file_save"`
	CollectFileSource       string   `toml:"collect_file_source"`
	CollectFileScope        string   `toml:"collect_file_scope"`
	FileSaveDedupSec        int      `toml:"file_save_dedup_sec"`
	FilterDefault           string   `toml:"filter_default"`
	Filter                  []string `toml:"filter"`
	CaptureFilter           []string `toml:"capture_filter"`
	CaptureFilterRefreshSec int      `toml:"capture_filter_refresh_sec"`
	UserOnly                bool     `toml:"user_only"`
	LostSamplesAction       string   `toml:"lost_samples_action"`
	MaxArgLength            int      `toml:"max_arg_length"`
	MaxArgs                 int      `toml:"max_args"`
}

func Default() Config {
	return Config{
		LogPath: DefaultLogPath,
		// Keep zstd as the default to reduce log size when config is not set.
		Compress:                CompressZstd,
		CompressLevel:           DefaultZstdCompressLevel,
		CollectFileOpen:         false,
		CollectFileSave:         false,
		CollectFileSource:       "user",
		CollectFileScope:        "user_visible",
		FileSaveDedupSec:        1,
		FilterDefault:           "allow",
		CaptureFilterRefreshSec: DefaultCaptureFilterRefreshSec,
		LostSamplesAction:       LostSamplesActionLog,
		MaxArgLength:            1024,
		MaxArgs:                 128,
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		path = DefaultConfigPath
	}

	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return Config{}, fmt.Errorf("read config: %w", err)
	}

	// Merge all included files before normalizing and validating runtime settings.
	compressLevelDefined, err := loadConfig(path, b, &cfg, nil)
	if err != nil {
		return Config{}, err
	}

	if cfg.LogPath == "" {
		cfg.LogPath = DefaultLogPath
	}
	cfg.Compress = strings.ToLower(strings.TrimSpace(cfg.Compress))
	if cfg.Compress == "" {
		cfg.Compress = CompressZstd
	}
	cfg.FilterDefault = strings.ToLower(strings.TrimSpace(cfg.FilterDefault))
	if cfg.FilterDefault == "" {
		cfg.FilterDefault = "allow"
	}
	if !compressLevelDefined {
		cfg.CompressLevel = defaultCompressLevel(cfg.Compress)
	}
	cfg.LostSamplesAction = strings.ToLower(strings.TrimSpace(cfg.LostSamplesAction))
	if cfg.LostSamplesAction == "" {
		cfg.LostSamplesAction = LostSamplesActionLog
	}
	cfg.CollectFileSource = strings.ToLower(strings.TrimSpace(cfg.CollectFileSource))
	if cfg.CollectFileSource == "" {
		cfg.CollectFileSource = "user"
	}
	cfg.CollectFileScope = strings.ToLower(strings.TrimSpace(cfg.CollectFileScope))
	if cfg.CollectFileScope == "" {
		cfg.CollectFileScope = "user_visible"
	}
	if cfg.MaxArgLength <= 0 {
		cfg.MaxArgLength = 1024
	}
	if cfg.MaxArgs <= 0 {
		cfg.MaxArgs = 128
	}
	if err := validateFileSaveDedupSec(cfg.FileSaveDedupSec); err != nil {
		return Config{}, err
	}
	if cfg.CaptureFilterRefreshSec <= 0 || int64(cfg.CaptureFilterRefreshSec) > int64((1<<63-1)/time.Second) {
		return Config{}, fmt.Errorf("invalid capture_filter_refresh_sec: %d (must be positive and fit in time.Duration)", cfg.CaptureFilterRefreshSec)
	}
	if err := validateCollectFileSource(cfg.CollectFileSource); err != nil {
		return Config{}, err
	}
	if err := validateCollectFileScope(cfg.CollectFileScope); err != nil {
		return Config{}, err
	}
	if err := validateCompression(cfg.Compress, cfg.CompressLevel); err != nil {
		return Config{}, err
	}
	if err := validateLostSamplesAction(cfg.LostSamplesAction); err != nil {
		return Config{}, err
	}
	if err := validateFilterDefault(cfg.FilterDefault); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func validateLegacyFilterKeys(meta toml.MetaData) error {
	legacyKeys := []string{
		"include_uids",
		"exclude_uids",
		"include_gids",
		"exclude_gids",
		"include_users",
		"exclude_users",
		"include_groups",
		"exclude_groups",
		"include_exe_prefixes",
		"exclude_exe_prefixes",
	}
	for _, key := range legacyKeys {
		if meta.IsDefined(key) {
			return fmt.Errorf("%s is no longer supported; use filter_default and filter", key)
		}
	}
	return nil
}

func validateFilterDefault(v string) error {
	switch v {
	case "allow", "deny":
		return nil
	default:
		return fmt.Errorf("invalid filter_default: %q (allowed: allow, deny)", v)
	}
}

func validateFileSaveDedupSec(v int) error {
	if v < 0 {
		return fmt.Errorf("invalid file_save_dedup_sec: %d (allowed: 0 or greater)", v)
	}
	return nil
}

func validateCollectFileSource(v string) error {
	switch v {
	case "user", "system", "any":
		return nil
	default:
		return fmt.Errorf("invalid collect_file_source: %q (allowed: user, system, any)", v)
	}
}

func validateCollectFileScope(v string) error {
	switch v {
	case "all", "home", "user_visible":
		return nil
	default:
		return fmt.Errorf("invalid collect_file_scope: %q (allowed: all, home, user_visible)", v)
	}
}

func defaultCompressLevel(mode string) int {
	switch mode {
	case CompressGzip:
		return DefaultGzipCompressLevel
	case CompressZstd:
		return DefaultZstdCompressLevel
	default:
		return 0
	}
}

func validateCompression(mode string, level int) error {
	switch mode {
	case CompressNo:
		return nil
	case CompressGzip:
		if level < -3 || level > 9 {
			return fmt.Errorf("invalid compress_level for compress=gz: %d (allowed: -3..9)", level)
		}
		return nil
	case CompressZstd:
		if level < 1 || level > 22 {
			return fmt.Errorf("invalid compress_level for compress=zstd: %d (allowed: 1..22)", level)
		}
		return nil
	default:
		return fmt.Errorf("invalid compress: %q (allowed: no, gz, zstd)", mode)
	}
}

func validateLostSamplesAction(action string) error {
	switch action {
	case LostSamplesActionLog, LostSamplesActionIgnore, LostSamplesActionStop:
		return nil
	default:
		return fmt.Errorf("invalid lost_samples_action: %q (allowed: log, ignore, stop)", action)
	}
}
