package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"

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
				Online:       false,
				IgnoreCert:   defaultbool(lastbool(yaml.IgnoreCert, cv.IgnoreCert, hv.IgnoreCert), false),
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
	return &Config{
		CheckInterval: yaml.CheckInterval,
		ListenPort:    yaml.ListenPort,
		Clusters:      clusters,
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
