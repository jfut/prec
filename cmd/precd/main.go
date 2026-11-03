// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright contributors to the prec project.

package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/alecthomas/kong"

	"github.com/jfut/prec/internal/collector"
	"github.com/jfut/prec/internal/config"
	"github.com/jfut/prec/internal/logger"
)

// Build metadata fields are injected by linker flags at build time.
var (
	version = "dev"
	commit  = "none"
)

// daemonCLI holds startup options for precd.
type daemonCLI struct {
	Config  string `name:"config" short:"c" help:"Path to config file (default: /etc/prec/precd.conf)"`
	Version bool   `name:"version" help:"Show version and build info"`
}

func main() {
	os.Exit(run())
}

func run() (exitCode int) {
	// Initialize defaults and parse arguments through kong.
	cli := daemonCLI{
		Config: config.DefaultConfigPath,
	}
	parser, err := kong.New(
		&cli,
		kong.Name("precd"),
		kong.UsageOnError(),
		kong.Writers(os.Stdout, os.Stderr),
	)
	if err != nil {
		log.Printf("init parser: %v", err)
		return 1
	}
	if _, err := parser.Parse(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	if cli.Version {
		fmt.Println(formatVersionInfo())
		return 0
	}

	if os.Geteuid() != 0 {
		log.Print("precd must run as root")
		return 1
	}

	cfg, err := config.Load(cli.Config)
	if err != nil {
		log.Printf("load config: %v", err)
		return 1
	}

	lock, err := acquireSingletonLock(cfg.LogPath)
	if err != nil {
		if errors.Is(err, errPrecdAlreadyRunning) {
			log.Printf("another precd instance is already running: %v", err)
			return 1
		}
		log.Printf("init singleton lock: %v", err)
		return 1
	}
	defer func() {
		if err := lock.Close(); err != nil {
			log.Printf("close singleton lock: %v", err)
			if exitCode == 0 {
				exitCode = 1
			}
		}
	}()

	w, err := logger.NewJSONLWriter(cfg.LogPath, cfg.Compress, cfg.CompressLevel)
	if err != nil {
		log.Printf("init logger: %v", err)
		return 1
	}
	defer func() {
		if err := w.Close(); err != nil {
			log.Printf("close logger: %v", err)
			if exitCode == 0 {
				exitCode = 1
			}
		}
	}()

	svc, err := collector.NewService(cfg, w)
	if err != nil {
		log.Printf("init collector: %v", err)
		return 1
	}

	stop := make(chan struct{})
	sigCh := make(chan os.Signal, 2)
	signalDone := make(chan struct{})
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigCh)
	defer close(signalDone)
	go func() {
		for {
			var sig os.Signal
			select {
			case sig = <-sigCh:
			case <-signalDone:
				return
			}
			switch sig {
			case syscall.SIGHUP:
				// Reopen the file descriptor after logrotate and append to the new file.
				if err := w.Reopen(); err != nil {
					log.Printf("reopen log file failed: %v", err)
				}
			case syscall.SIGINT, syscall.SIGTERM:
				close(stop)
				return
			}
		}
	}()

	if err := svc.Run(stop); err != nil {
		log.Printf("run collector: %v", err)
		return 1
	}
	return 0
}

// formatVersionInfo builds a single-line version string for --version output.
func formatVersionInfo() string {
	return fmt.Sprintf(
		"precd %s (%s)",
		version,
		commit,
	)
}
