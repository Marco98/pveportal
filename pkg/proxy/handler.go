package proxy

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
			cname, err = url.QueryUnescape(cl.Value)
			if err != nil {
				log.WithError(err).Error("failed to unescape cookie")
			}
		}
		cluster := getCluster(cfg, cname)
		if cluster == nil {
			cluster = &cfg.Clusters[0]
			http.SetCookie(w, &http.Cookie{
				Name:  clusterCookieName,
				Value: url.QueryEscape(cluster.Name),
				Path:  "/",
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
				Proxy: http.ProxyFromEnvironment,
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
	bb, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(r.Method, tgturl.String(), bytes.NewReader(bb))
	if err != nil {
		return err
	}
	copyHeaders(r.Header, req.Header)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	copyHeaders(resp.Header, w.Header())
	w.WriteHeader(resp.StatusCode)
	if host.HideRepowarn && r.URL.Path == "/api2/extjs/nodes/localhost/subscription" {
		return mangleSubscription(resp.Body, w)
	}
	if r.URL.Path == "/" {
		return injectScript(resp.Body, w, localHTTPDir+"portal.js")
	}
	if _, err := io.Copy(w, resp.Body); err != nil {
		return err
	}
	return nil
}

func copyHeaders(src http.Header, dst http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			if k == "Content-Length" ||
				k == "Transfer-Encoding" ||
				k == "Accept-Encoding" {
				continue
			}
			dst.Add(k, v)
		}
	}
}

func mangleSubscription(r io.Reader, w io.Writer) error {
	body, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte(strings.Replace(string(body), "\"status\":\"notfound\"", "\"status\":\"active\"", 1))); err != nil {
		return err
	}
	return nil
}

func injectScript(r io.Reader, w io.Writer, path string) error {
	body, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	ref := fmt.Sprintf("  <script type=\"text/javascript\" src=\"%s\"></script>\n  </head>", path)
	if _, err := w.Write([]byte(strings.Replace(string(body), "</head>", ref, 1))); err != nil {
		return err
	}
	return nil
}
