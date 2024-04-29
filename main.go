package main

import (
	"github.com/Marco98/pveportal/pkg/proxy"
	log "github.com/sirupsen/logrus"
)

func main() {
	if err := proxy.Run(); err != nil {
		log.WithError(err).Fatal("fatal exception")
	}
}
