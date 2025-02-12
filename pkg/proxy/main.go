package proxy

import (
	"context"
	"crypto/tls"
	"embed"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Marco98/pveportal/pkg/config"
)

const (
	clusterCookieName = "PvePortalClusterName"
	sessionCookieName = "PvePortalSession"
	localHTTPDir      = "/pveportal/"
)

var errProxyWs = errors.New("error while proxing ws")

var logLevels = map[string]slog.Level{
	"debug": slog.LevelDebug,
	"info":  slog.LevelInfo,
	"warn":  slog.LevelWarn,
	"error": slog.LevelError,
}

func Run(www embed.FS) error {
	cpath := flag.String("c", "pveportal.yaml", "config path")
	logLevel := flag.String("l", "INFO", "loglevel")
	flag.Parse()
	slogLevel, ok := logLevels[strings.ToLower(*logLevel)]
	if !ok {
		return fmt.Errorf("invalid loglevel: %s", *logLevel)
	}
	slog.SetLogLoggerLevel(slogLevel)
	cfg, err := config.ParseConfigfile(*cpath)
	if err != nil {
		return err
	}
	staticFS := fs.FS(www)
	htmlContent, err := fs.Sub(staticFS, "www")
	if err != nil {
		return err
	}
	prx, err := NewProxy(cfg)
	if err != nil {
		return err
	}
	defer prx.close()
	tlscfg, err := prx.parseTLSConfig()
	if err != nil {
		return err
	}
	fs := http.FileServer(http.FS(htmlContent))
	http.HandleFunc(fmt.Sprintf("%sapi/clusters", localHTTPDir), prx.applyHstsFunc(listClusters(cfg.Clusters)))
	http.HandleFunc(fmt.Sprintf("%sapi/switchcluster", localHTTPDir), prx.applyHstsFunc(switchCluster()))
	http.Handle(localHTTPDir, prx.applyHsts(http.StripPrefix(localHTTPDir, fs)))
	http.HandleFunc("/", prx.applyHstsFunc(prx.proxyHandler()))
	srv := &http.Server{
		ReadTimeout:  time.Duration(cfg.ServerTimeoutRead) * time.Second,
		WriteTimeout: time.Duration(cfg.ServerTimeoutWrite) * time.Second,
		Addr:         fmt.Sprintf(":%d", cfg.ListenPort),
		TLSConfig:    tlscfg,
		// disable HTTP/2 as not supported by PVE
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		ErrorLog:     slog.NewLogLogger(slog.Default().Handler(), slog.LevelWarn),
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
			slog.Error("api cannot listen", "error", err)
			endsig <- syscall.SIGTERM
		}
	}()
	cleanctx, cleancancel := context.WithCancel(context.Background())
	go prx.cleanSessions(cleanctx)
	if prx.config.CheckInterval >= 0 {
		slog.Debug("healthcheck enabled", "interval", prx.config.CheckInterval)
		go prx.hostHealthchecks(cleanctx)
	}
	<-endsig
	cleancancel()
	slog.Info("shutting down server")
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
	if len(p.config.TLSKeyFile) == 0 || len(p.config.TLSCertFile) == 0 {
		return nil, nil
	}
	crt, err := tls.LoadX509KeyPair(p.config.TLSCertFile, p.config.TLSKeyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{crt},
		MinVersion:   tls.VersionTLS12,
		KeyLogWriter: p.sslKeyLogFile,
	}, nil
}

func (p *Proxy) getClusterFailSite(wr io.Writer) error {
	tmplRaw := `<!DOCTYPE html>
	<html>
	<head>
		<title>cluster unreachable</title>
	</head>
	<body>
		<p>cluster unreachable</p><br>
		<p>switch clusters?</p>
		<li>
		{{range $c := .}}
			<ul><a href="{{$c.SwitchURL}}">{{$c.Name}}</a></ul>
		{{end}}
		</li>
	</body>
	</html>`
	tmpl, err := template.New("clusterFailSite").Parse(tmplRaw)
	if err != nil {
		return err
	}
	clusters := make([]listClustersCluster, 0)
	for _, v := range p.config.Clusters {
		clusters = append(clusters, listClustersCluster{
			Name:      v.Name,
			SwitchURL: fmt.Sprintf("%sapi/switchcluster?name=%s", localHTTPDir, url.QueryEscape(v.Name)),
		})
	}
	return tmpl.Execute(wr, clusters)
}

func (p *Proxy) hostHealthchecks(ctx context.Context) {
	for {
		time.Sleep(time.Duration(p.config.CheckInterval) * time.Second)
		slog.Debug("healthcheck interval started")
		if ctx.Err() != nil {
			return
		}
		for clx, cl := range p.config.Clusters {
			for chx, ch := range cl.Hosts {
				log := slog.With(
					"cluster", cl.Name,
					"host", ch.Name,
				)
				log.Debug("healthcheck dialing", "addr", ch.Endpoint.Host)
				c, err := net.Dial("tcp", ch.Endpoint.Host)
				if err != nil {
					if ch.Online {
						p.config.Clusters[clx].Hosts[chx].Online = false
						log.Warn("host state: UP => DOWN", "error", err)
					}
					continue
				}
				c.Close()
				if !ch.Online {
					p.config.Clusters[clx].Hosts[chx].Online = true
					log.Warn("host state: DOWN => UP")
				}
			}
		}
		slog.Debug("healthcheck interval ended")
	}
}
