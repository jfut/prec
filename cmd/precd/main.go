package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/alecthomas/kong"

	"github.com/jfut/prec/pkg/collector"
	"github.com/jfut/prec/pkg/config"
	"github.com/jfut/prec/pkg/logger"
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
		log.Fatalf("init parser: %v", err)
	}
	if _, err := parser.Parse(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if cli.Version {
		fmt.Println(formatVersionInfo())
		return
	}

	if os.Geteuid() != 0 {
		log.Fatal("precd must run as root")
	}

	cfg, err := config.Load(cli.Config)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	w, err := logger.NewJSONLWriter(cfg.LogPath, cfg.Compress, cfg.CompressLevel)
	if err != nil {
		log.Fatalf("init logger: %v", err)
	}
	defer w.Close()

	svc, err := collector.NewService(cfg, w)
	if err != nil {
		log.Fatalf("init collector: %v", err)
	}

	stop := make(chan struct{})
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigCh)
	go func() {
		for sig := range sigCh {
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
		log.Fatalf("run collector: %v", err)
	}
}

// formatVersionInfo builds a single-line version string for --version output.
func formatVersionInfo() string {
	return fmt.Sprintf(
		"precd %s (%s)",
		version,
		commit,
	)
}
