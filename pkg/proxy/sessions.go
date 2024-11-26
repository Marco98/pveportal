package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Marco98/pveportal/pkg/config"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type SessionData struct {
	Ticket              string
	CSRFPreventionToken string
	Username            string
	Expiration          time.Time
}

type Proxy struct {
	config        *config.Config
	sessions      map[uuid.UUID]map[string]SessionData
	sessionsLock  *sync.RWMutex
	httpClient    *http.Client
	sslKeyLogFile io.WriteCloser
}

func NewProxy(config *config.Config) (*Proxy, error) {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: config.TLSIgnoreCert, //nolint:gosec,G402
		},
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		// disable HTTP/2 as not supported by PVE
		TLSNextProto:      make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
		ForceAttemptHTTP2: false,
	}
	p := &Proxy{
		sessions:     make(map[uuid.UUID]map[string]SessionData),
		sessionsLock: &sync.RWMutex{},
		config:       config,
		httpClient: &http.Client{
			Transport: transport,
		},
	}
	path := os.Getenv("SSLKEYLOGFILE")
	if len(path) != 0 {
		var err error
		p.sslKeyLogFile, err = os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
		if err != nil {
			return nil, fmt.Errorf("could not open SSLKEYLOGFILE: %w", err)
		}
		transport.TLSClientConfig.KeyLogWriter = p.sslKeyLogFile
	}
	return p, nil
}

func (p *Proxy) close() {
	if p.sslKeyLogFile != nil {
		p.sslKeyLogFile.Close()
	}
}

func (p *Proxy) passthroughAuthSession(w http.ResponseWriter, r *http.Request) error {
	if !p.config.PassthroughAuth {
		return nil
	}
	c, err := r.Cookie(sessionCookieName)
	if err != nil && !errors.Is(err, http.ErrNoCookie) {
		return p.newPassthroughAuthSession(w)
	}
	if c == nil {
		return p.newPassthroughAuthSession(w)
	}
	if _, err := uuid.Parse(c.Value); err != nil {
		return p.newPassthroughAuthSession(w)
	}
	return nil
}

func (p *Proxy) newPassthroughAuthSession(w http.ResponseWriter) error {
	http.SetCookie(w, &http.Cookie{
		Name:   sessionCookieName,
		Value:  uuid.NewString(),
		Secure: true,
		Path:   "/",
	})
	return nil
}

func (p *Proxy) multiAuth(log logrus.FieldLogger, w http.ResponseWriter, r *http.Request) error {
	if err := r.ParseForm(); err != nil {
		return err
	}
	isRenew := strings.HasPrefix(r.Form.Get("password"), "PVE:")
	atLeastOneOK := false
	var lastresp http.Response
	var lastrespb []byte
	rsid, err := r.Cookie(sessionCookieName)
	if err != nil {
		return err
	}
	sid, err := uuid.Parse(rsid.Value)
	if err != nil {
		return err
	}
	errcnt := 0
	for _, v := range p.config.Clusters {
		if p.config.PassthroughAuthMaxfail > 0 && errcnt >= p.config.PassthroughAuthMaxfail {
			return errors.New("passthrough error limit reached")
		}
		host := getHealthyHost(v.Hosts)
		tgturl := *r.URL
		tgturl.Scheme = host.Endpoint.Scheme
		tgturl.Host = host.Endpoint.Host
		log = log.WithFields(logrus.Fields{
			"host":    tgturl.Host,
			"cluster": v.Name,
			"renew":   isRenew,
			"errcnt":  errcnt,
			"errmax":  p.config.PassthroughAuthMaxfail,
		})
		if isRenew {
			sd := p.getSessionData(sid, v.Name)
			if sd != nil {
				r.Form.Set("password", sd.Ticket)
			} else {
				log.Warn("existing ticket missing for renew")
			}
		}
		req, err := http.NewRequestWithContext(r.Context(), r.Method, tgturl.String(), strings.NewReader(r.Form.Encode()))
		if err != nil {
			log.WithError(err).Error("failed multiauth connection prep")
			errcnt++
			continue
		}
		p.copyHeaders(r.Header, req.Header)
		resp, err := p.httpClient.Do(req)
		if err != nil {
			log.WithError(err).Error("failed multiauth connection open")
			errcnt++
			continue
		}
		defer resp.Body.Close()
		vb, err := io.ReadAll(resp.Body)
		if err != nil {
			log.WithError(err).Error("failed multiauth connection read")
			errcnt++
			continue
		}
		if err := p.registerSession(log, sid, v.Name, vb); err != nil {
			log.WithError(err).Error("failed multiauth response registration")
			errcnt++
			continue
		}
		lastresp = *resp
		lastrespb = vb
		atLeastOneOK = true
	}
	if !atLeastOneOK {
		return errors.New("failed multiauth on all hosts")
	}
	p.copyHeaders(lastresp.Header, w.Header())
	w.WriteHeader(lastresp.StatusCode)
	_, err = io.Copy(w, bytes.NewBuffer(lastrespb))
	return err
}

func (p *Proxy) registerSession(log logrus.FieldLogger, sid uuid.UUID, cluster string, resp []byte) error {
	d := &struct {
		Success int `json:"success"`
		Data    struct {
			Ticket              string `json:"ticket"`
			Username            string `json:"username"`
			CSRFPreventionToken string `json:"CSRFPreventionToken"`
		} `json:"data"`
	}{}
	if err := json.Unmarshal(resp, d); err != nil {
		return err
	}
	if len(d.Data.Ticket) == 0 {
		return fmt.Errorf("ticket length is zero: %s", cluster)
	}
	p.sessionsLock.Lock()
	defer p.sessionsLock.Unlock()
	if _, ok := p.sessions[sid]; !ok {
		p.sessions[sid] = make(map[string]SessionData)
	}
	p.sessions[sid][cluster] = SessionData{
		Ticket:              d.Data.Ticket,
		CSRFPreventionToken: d.Data.CSRFPreventionToken,
		Expiration:          time.Now().Add(p.config.SessionTime),
		Username:            d.Data.Username,
	}
	log.WithFields(logrus.Fields{
		"cluster":  cluster,
		"username": d.Data.Username,
	}).Info("registered session")
	return nil
}

func (s *SessionData) createAuthCookie() *http.Cookie {
	return &http.Cookie{
		Name:  "PVEAuthCookie",
		Value: s.Ticket,
		Path:  "/",
	}
}

func (p *Proxy) mangleCookies(cluster string, oreq *http.Request, nreq *http.Request) error {
	nreq.Header.Del("Cookie")
	for _, c := range oreq.Cookies() {
		if c.Name != "PVEAuthCookie" &&
			c.Name != clusterCookieName &&
			c.Name != sessionCookieName {
			nreq.AddCookie(c)
		}
	}
	rsid, err := oreq.Cookie(sessionCookieName)
	if errors.Is(err, http.ErrNoCookie) {
		return nil
	}
	if err != nil {
		return err
	}
	sid, err := uuid.Parse(rsid.Value)
	if err != nil {
		return err
	}
	if c := p.getSessionData(sid, cluster); c != nil {
		nreq.AddCookie(c.createAuthCookie())
		nreq.Header.Set("CSRFPreventionToken", c.CSRFPreventionToken)
	}
	return nil
}

func (p *Proxy) getSessionData(sid uuid.UUID, cluster string) *SessionData {
	p.sessionsLock.RLock()
	defer p.sessionsLock.RUnlock()
	cc, ok := p.sessions[sid]
	if !ok {
		return nil
	}
	c, ok := cc[cluster]
	if !ok {
		return nil
	}
	return &c
}

func (p *Proxy) cleanSessions(ctx context.Context) {
	for {
		time.Sleep(60 * time.Second)
		if ctx.Err() != nil {
			return
		}
		p.sessionsLock.Lock()
		for k, v := range p.sessions {
			for ck, cv := range v {
				if time.Now().After(cv.Expiration) {
					delete(v, ck)
					logrus.WithFields(logrus.Fields{
						"cluster":  ck,
						"username": cv.Username,
					}).Info("session expired")
				}
			}
			if len(p.sessions[k]) == 0 {
				delete(p.sessions, k)
			}
		}
		p.sessionsLock.Unlock()
	}
}
