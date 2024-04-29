package proxy

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/Marco98/pveportal/pkg/config"
	log "github.com/sirupsen/logrus"
)

func proxyHandler(cfg *config.Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		cl, err := r.Cookie(clusterCookieName)
		if err != nil && !errors.Is(err, http.ErrNoCookie) {
			log.WithError(err).Error("failed to access cookie")
		}
		cname := ""
		if cl != nil {
			cname = cl.Value
		}
		cluster := getCluster(cfg, cname)
		if cluster == nil {
			cluster = &cfg.Clusters[0]
			http.SetCookie(w, &http.Cookie{
				Name:  clusterCookieName,
				Value: cluster.Name,
			})
		}
		host := getHealthyHost(cluster.Hosts)
		log.WithFields(log.Fields{
			"url":     r.URL.String(),
			"cluster": cluster.Name,
			"host":    host.Name,
		}).Debug("accessed backend")
		if err := proxyRequest(host, w, r); err != nil {
			log.WithError(err).Error("failed to proxy request")
			if _, err := io.WriteString(w, "failed to proxy request"); err != nil {
				log.WithError(err).Error("error writing error to response")
			}
		}
	}
}

func proxyRequest(host *config.Host, w http.ResponseWriter, r *http.Request) error {
	client := host.Client
	if client == nil {
		client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: host.IgnoreCert, //nolint:gosec,G402
				},
			},
		}
		host.Client = client
		log.Debug("created new http client")
	}
	tgturl := *r.URL
	tgturl.Scheme = host.Endpoint.Scheme
	tgturl.Host = host.Endpoint.Host
	oreqbody, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	oreqbuf := bytes.NewBuffer(oreqbody)
	req, err := http.NewRequest(r.Method, tgturl.String(), oreqbuf)
	if err != nil {
		return err
	}
	req.Header = r.Header
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if host.HideRepowarn && tgturl.Path == "/api2/extjs/nodes/localhost/subscription" {
		body = []byte(strings.Replace(string(body), "\"status\":\"notfound\"", "\"status\":\"active\"", 1))
	}
	for k, vv := range resp.Header {
		for _, v := range vv {
			if k == "Content-Length" {
				continue
			}
			w.Header().Add(k, v)
		}
	}
	if _, err := w.Write(body); err != nil {
		return err
	}
	return nil
}
