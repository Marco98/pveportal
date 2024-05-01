package proxy

import (
	"context"
	"embed"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Marco98/pveportal/pkg/config"
	log "github.com/sirupsen/logrus"
)

const (
	clusterCookieName = "PvePortalClusterName"
	localHTTPDir      = "/pveportal/"
)

func Run(www embed.FS) error {
	cpath := flag.String("c", "pveportal.yaml", "config path")
	loglevel := flag.String("l", "INFO", "loglevel")
	flag.Parse()
	llevel, err := log.ParseLevel(*loglevel)
	if err != nil {
		return err
	}
	log.SetLevel(llevel)
	cfg, err := config.ParseConfigfile(*cpath)
	if err != nil {
		return err
	}

	staticFS := fs.FS(www)
	htmlContent, err := fs.Sub(staticFS, "www")
	if err != nil {
		return err
	}
	fs := http.FileServer(http.FS(htmlContent))
	http.HandleFunc(fmt.Sprintf("%sapi/clusters", localHTTPDir), listClusters(cfg.Clusters))
	http.HandleFunc(fmt.Sprintf("%sapi/switchcluster", localHTTPDir), switchCluster())
	http.Handle(localHTTPDir, http.StripPrefix(localHTTPDir, fs))

	handler := proxyHandler(cfg)
	http.HandleFunc("/", handler)

	srv := &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		Addr:         fmt.Sprintf(":%d", cfg.ListenPort),
	}

	endsig := make(chan os.Signal, 1)
	signal.Notify(endsig, os.Interrupt, syscall.SIGTERM)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.WithError(err).Error("api cannot listen")
			endsig <- syscall.SIGTERM
		}
	}()
	<-endsig
	log.Info("shutting down server")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer func() {
		cancel()
	}()

	if err := srv.Shutdown(ctx); err != nil {
		return err
	}
	return nil
}

func getCluster(cfg *config.Config, cluster string) *config.Cluster {
	for _, v := range cfg.Clusters {
		if v.Name == cluster {
			return &v
		}
	}
	return nil
}

func getHealthyHost(hh []config.Host) *config.Host {
	for _, v := range hh {
		if v.Online {
			return &v
		}
	}
	return &hh[0]
}
