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
	"sync"
	"time"

	"github.com/Marco98/pveportal/pkg/config"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type Proxy struct {
	config       *config.Config
	sessions     map[uuid.UUID]map[string]http.Cookie
	sessionsLock *sync.RWMutex
}

func NewProxy(config *config.Config) *Proxy {
	return &Proxy{
		sessions:     make(map[uuid.UUID]map[string]http.Cookie),
		sessionsLock: &sync.RWMutex{},
		config:       config,
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
	oreq, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	resps := make(map[string]http.Response)
	for _, v := range p.config.Clusters {
		host := getHealthyHost(v.Hosts)
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
		log = log.WithFields(logrus.Fields{
			"tgturl":  tgturl.String(),
			"cluster": v.Name,
		})
		req, err := http.NewRequestWithContext(r.Context(), r.Method, tgturl.String(), bytes.NewReader(oreq))
		if err != nil {
			log.WithError(err).Error("failed multiauth")
			continue
		}
		p.copyHeaders(r.Header, req.Header)
		resp, err := client.Do(req)
		if err != nil {
			log.WithError(err).Error("failed multiauth")
			continue
		}
		defer resp.Body.Close()
		resps[v.Name] = *resp
	}
	lastrespok := false
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
	for k, v := range resps {
		vb, err := io.ReadAll(v.Body)
		if err != nil {
			return err
		}
		if err := p.registerSession(log, sid, k, vb); err != nil {
			log.WithError(err).Error("failed multiauth response")
			continue
		}
		lastresp = v
		lastrespb = vb
		lastrespok = true
	}
	if !lastrespok {
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
			Ticket   string `json:"ticket"`
			Username string `json:"username"`
		} `json:"data"`
	}{}
	if err := json.Unmarshal(resp, d); err != nil {
		return err
	}
	if d.Success != 1 {
		return fmt.Errorf("success != 1 in cluster: %s", cluster)
	}
	p.sessionsLock.Lock()
	defer p.sessionsLock.Unlock()
	if _, ok := p.sessions[sid]; !ok {
		p.sessions[sid] = make(map[string]http.Cookie)
	}
	p.sessions[sid][cluster] = http.Cookie{
		Name:    "PVEAuthCookie",
		Value:   d.Data.Ticket,
		Path:    "/",
		Expires: time.Now().Add(p.config.SessionTime),
	}
	log.WithFields(logrus.Fields{
		"cluster":  cluster,
		"username": d.Data.Username,
	}).Info("registered session")
	return nil
}

func (p *Proxy) addAuthCookie(cluster string, r *http.Request, h http.Header) error {
	rsid, err := r.Cookie(sessionCookieName)
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
	h.Add("Cookie", c.String())
	return nil
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
				if time.Now().After(cv.Expires) {
					delete(v, ck)
				}
			}
			if len(p.sessions[k]) == 0 {
				delete(p.sessions, k)
			}
		}
		p.sessionsLock.Unlock()
	}
}
