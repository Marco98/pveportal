package proxy

import (
	"context"
	"crypto/tls"
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
	"github.com/sirupsen/logrus"
)

const (
	clusterCookieName = "PvePortalClusterName"
	sessionCookieName = "PvePortalSession"
	localHTTPDir      = "/pveportal/"
)

func Run(www embed.FS) error {
	cpath := flag.String("c", "pveportal.yaml", "config path")
	loglevel := flag.String("l", "INFO", "loglevel")
	flag.Parse()
	llevel, err := logrus.ParseLevel(*loglevel)
	if err != nil {
		return err
	}
	logrus.SetLevel(llevel)
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
	prx := NewProxy(cfg)
	handler := prx.proxyHandler()
	http.HandleFunc("/", handler)
	tlscfg, err := prx.parseTLSConfig()
	if err != nil {
		return err
	}
	srv := &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		Addr:         fmt.Sprintf(":%d", cfg.ListenPort),
		TLSConfig:    tlscfg,
	}

	endsig := make(chan os.Signal, 1)
	signal.Notify(endsig, os.Interrupt, syscall.SIGTERM)
	go func() {
		var err error
		if srv.TLSConfig != nil {
			err = srv.ListenAndServeTLS("", "")
		} else {
			err = srv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logrus.WithError(err).Error("api cannot listen")
			endsig <- syscall.SIGTERM
		}
	}()
	cleanctx, cleancancel := context.WithCancel(context.Background())
	go prx.cleanSessions(cleanctx)
	<-endsig
	cleancancel()
	logrus.Info("shutting down server")
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

func (p *Proxy) parseTLSConfig() (*tls.Config, error) {
	if len(p.config.TLSKeyFile) == 0 && len(p.config.TLSCertFile) == 0 {
		return nil, nil
	}
	crt, err := tls.LoadX509KeyPair(p.config.TLSCertFile, p.config.TLSKeyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{crt},
		MinVersion:   tls.VersionTLS12,
	}, nil
}
