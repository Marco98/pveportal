package main

import (
	"embed"
	"log/slog"
	"os"

	"github.com/Marco98/pveportal/pkg/proxy"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

//go:embed www
var www embed.FS

func main() {
	slog.Info(
		"starting pveportal",
		"version", version,
		"commit", commit,
		"date", date,
	)
	if err := proxy.Run(www); err != nil {
		slog.Error("fatal exception", "error", err)
		os.Exit(1)
	}
}
