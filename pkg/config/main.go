package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

func ParseConfigfile(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	d := yaml.NewDecoder(f)
	yconf := new(YamlConfig)
	if err := d.Decode(yconf); err != nil {
		return nil, err
	}
	return parseConfig(yconf)
}

func parseConfig(yaml *YamlConfig) (*Config, error) {
	clusters := make([]Cluster, len(yaml.Clusters))
	if len(yaml.Clusters) == 0 {
		return nil, errors.New("no clusters defined")
	}
	for ci, cv := range yaml.Clusters {
		if len(cv.Hosts) == 0 {
			return nil, fmt.Errorf("no host defined in cluster \"%s\"", cv.Name)
		}
		hosts := make([]Host, len(cv.Hosts))
		for hi, hv := range cv.Hosts {
			ep, err := url.Parse(hv.Endpoint)
			if err != nil {
				return nil, fmt.Errorf("could not parse endpoint: %w", err)
			}
			user := laststr(yaml.Username, cv.Username, hv.Username)
			pass := laststr(yaml.Password, cv.Password, hv.Password)
			if len(user) == 0 || len(pass) == 0 {
				return nil, errors.New("credentials missing")
			}
			hosts[hi] = Host{
				Name:         hv.Name,
				Endpoint:     ep,
				Online:       true,
				HideRepowarn: defaultbool(lastbool(yaml.HideRepowarn, cv.HideRepowarn, hv.HideRepowarn), false),
				Username:     user,
				Password:     pass,
			}
		}
		clusters[ci] = Cluster{
			Name:  cv.Name,
			Hosts: hosts,
		}
	}
	sessionTime := time.Hour * 12
	if len(yaml.SessionTime) > 0 {
		var err error
		sessionTime, err = time.ParseDuration(yaml.SessionTime)
		if err != nil {
			return nil, fmt.Errorf("could not parse sessiontime: %w", err)
		}
	}
	if yaml.ListenPort == 0 {
		yaml.ListenPort = 80
		if len(yaml.TLSCertFile) > 0 && len(yaml.TLSKeyFile) > 0 {
			yaml.ListenPort = 443
		}
	}
	return &Config{
		CheckInterval:          defaultint(yaml.CheckInterval, 60),
		ListenPort:             yaml.ListenPort,
		Clusters:               clusters,
		PassthroughAuth:        defaultbool(yaml.PassthroughAuth, false),
		PassthroughAuthMaxfail: defaultint(yaml.PassthroughAuthMaxfail, 0),
		SessionTime:            sessionTime,
		TLSCertFile:            yaml.TLSCertFile,
		TLSKeyFile:             yaml.TLSKeyFile,
		TLSIgnoreCert:          defaultbool(yaml.TLSIgnoreCert, false),
		ServerTimeoutWrite:     defaultint(yaml.ServerTimeoutWrite, 600),
		ServerTimeoutRead:      defaultint(yaml.ServerTimeoutRead, 600),
	}, nil
}

func laststr(strs ...string) string {
	var str string
	for _, v := range strs {
		if len(v) > 0 {
			str = v
		}
	}
	return str
}

func lastbool(bools ...*bool) *bool {
	var bol *bool
	for _, v := range bools {
		if v != nil {
			bol = v
		}
	}
	return bol
}

func defaultbool(b *bool, def bool) bool {
	if b != nil {
		return *b
	}
	return def
}

func defaultint(i *int, def int) int {
	if i == nil {
		return def
	}
	return *i
}
