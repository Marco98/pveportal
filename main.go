package main

import (
	"embed"

	"github.com/Marco98/pveportal/pkg/proxy"
	"github.com/sirupsen/logrus"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

//go:embed www
var www embed.FS

func main() {
	logrus.WithFields(logrus.Fields{
		"version": version,
		"commit":  commit,
		"date":    date,
	}).Info("starting pveportal")
	if err := proxy.Run(www); err != nil {
		logrus.WithError(err).Fatal("fatal exception")
	}
}
