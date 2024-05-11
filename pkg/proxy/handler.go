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
	"github.com/sirupsen/logrus"
)

func (p *Proxy) proxyHandler() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		log := logrus.WithFields(logrus.Fields{
			"remoteAddr": r.RemoteAddr,
			"url":        r.URL.String(),
		})
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
		cluster := getCluster(p.config, cname)
		if cluster == nil {
			cluster = &p.config.Clusters[0]
			http.SetCookie(w, &http.Cookie{
				Name:  clusterCookieName,
				Value: url.QueryEscape(cluster.Name),
				Path:  "/",
			})
		}
		log = log.WithField("cluster", cluster.Name)
		if err := p.passthroughAuthSession(w, r); err != nil {
			log.WithError(err).Error("error handling passthrough auth session")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if p.config.PassthroughAuth && r.URL.Path == "/api2/extjs/access/ticket" {
			if err := p.multiAuth(log, w, r); err != nil {
				log.WithError(err).Error("error handling passthrough auth multiauth")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			return
		}
		host := getHealthyHost(cluster.Hosts)
		log.WithField("host", host.Name).Debug("accessed backend")
		if err := p.proxyRequest(cluster.Name, host, w, r); err != nil {
			log.WithError(err).Error("failed to proxy request")
			if _, err := io.WriteString(w, "failed to proxy request"); err != nil {
				log.WithError(err).Error("error writing error to response")
			}
		}
	}
}

func (p *Proxy) proxyRequest(cluster string, host *config.Host, w http.ResponseWriter, r *http.Request) error {
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: host.IgnoreCert, //nolint:gosec,G402
			},
		},
	}
	tgturl := *r.URL
	tgturl.Scheme = host.Endpoint.Scheme
	tgturl.Host = host.Endpoint.Host
	bb, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, tgturl.String(), bytes.NewReader(bb))
	if err != nil {
		return err
	}
	p.copyHeaders(r.Header, req.Header)
	if p.config.PassthroughAuth {
		if err := p.addAuthCookie(cluster, r, req.Header); err != nil {
			return err
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	p.copyHeaders(resp.Header, w.Header())
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

func (p *Proxy) copyHeaders(src http.Header, dst http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			if k == "Content-Length" ||
				k == "Transfer-Encoding" ||
				k == "Accept-Encoding" ||
				(p.config.PassthroughAuth && k == "Cookie") {
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
