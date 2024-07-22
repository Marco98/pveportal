package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Marco98/pveportal/pkg/config"
	"github.com/gorilla/websocket"
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
			if errors.Is(err, context.Canceled) {
				log.WithError(err).Debug("failed to proxy request")
			} else {
				log.WithError(err).Error("failed to proxy request")
			}
			if err := p.getClusterFailSite(w); err != nil {
				log.WithError(err).Error("error writing error to response")
			}
		}
	}
}

func (p *Proxy) proxyRequest(cluster string, host *config.Host, w http.ResponseWriter, r *http.Request) error {
	tgturl := *r.URL
	tgturl.Scheme = host.Endpoint.Scheme
	tgturl.Host = host.Endpoint.Host
	if len(r.Header.Get("Sec-WebSocket-Protocol")) != 0 {
		if tgturl.Scheme == "http" {
			tgturl.Scheme = "ws"
		}
		if tgturl.Scheme == "https" {
			tgturl.Scheme = "wss"
		}
		return p.proxyWebsocket(cluster, host, w, r, tgturl)
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, tgturl.String(), r.Body)
	if err != nil {
		return err
	}
	req.ContentLength = r.ContentLength
	p.copyHeaders(r.Header, req.Header)
	if p.config.PassthroughAuth {
		if err := p.addAuthCookie(cluster, r, req.Header); err != nil {
			return err
		}
	}
	resp, err := p.httpClient.Do(req)
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
				(p.config.PassthroughAuth && k == "Cookie") ||
				k == "Sec-Websocket-Version" ||
				k == "Connection" ||
				k == "Upgrade" ||
				k == "Sec-Websocket-Extensions" ||
				k == "Sec-WebSocket-Accept" ||
				k == "Sec-Websocket-Key" {
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

func (p *Proxy) proxyWebsocket(cluster string, host *config.Host, w http.ResponseWriter, r *http.Request, tgturl url.URL) error {
	dialer := &websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 45 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: host.IgnoreCert, //nolint:gosec,G402
		},
	}
	bhead := http.Header{}
	p.copyHeaders(r.Header, bhead)
	if p.config.PassthroughAuth {
		if err := p.addAuthCookie(cluster, r, bhead); err != nil {
			return err
		}
	}
	bcon, resp, err := dialer.Dial(tgturl.String(), bhead)
	if err != nil {
		return fmt.Errorf("failed dialing backend: %w", err)
	}
	defer bcon.Close()
	upgrader := &websocket.Upgrader{}
	fhead := http.Header{}
	if hdr := resp.Header.Get("Sec-Websocket-Protocol"); hdr != "" {
		fhead.Set("Sec-Websocket-Protocol", hdr)
	}
	if hdr := resp.Header.Get("Set-Cookie"); hdr != "" {
		fhead.Set("Set-Cookie", hdr)
	}
	fcon, err := upgrader.Upgrade(w, r, fhead)
	if err != nil {
		return fmt.Errorf("failed upgrading frontend: %w", err)
	}
	defer fcon.Close()
	ferr := make(chan error, 1)
	berr := make(chan error, 1)
	go replicateWebsocketConn(fcon, bcon, ferr)
	go replicateWebsocketConn(bcon, fcon, berr)
	select {
	case err = <-ferr:
	case err = <-berr:
	}
	if e, ok := err.(*websocket.CloseError); !ok || e.Code == websocket.CloseAbnormalClosure {
		return fmt.Errorf("error while proxing ws: %w", err)
	}
	return nil
}

func replicateWebsocketConn(dst, src *websocket.Conn, errc chan error) {
	for {
		msgType, msg, err := src.ReadMessage()
		if err != nil {
			m := websocket.FormatCloseMessage(websocket.CloseNormalClosure, fmt.Sprintf("%v", err))
			if e, ok := err.(*websocket.CloseError); ok {
				if e.Code != websocket.CloseNoStatusReceived {
					m = nil
					if e.Code != websocket.CloseAbnormalClosure && e.Code != websocket.CloseTLSHandshake {
						m = websocket.FormatCloseMessage(e.Code, e.Text)
					}
				}
			}
			errc <- err
			if m != nil {
				_ = dst.WriteMessage(websocket.CloseMessage, m)
			}
			break
		}
		err = dst.WriteMessage(msgType, msg)
		if err != nil {
			errc <- err
			break
		}
	}
}
