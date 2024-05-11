package main

import (
	"embed"

	"github.com/Marco98/pveportal/pkg/proxy"
	"github.com/sirupsen/logrus"
)

//go:embed www
var www embed.FS

func main() {
	if err := proxy.Run(www); err != nil {
		logrus.WithError(err).Fatal("fatal exception")
	}
}
