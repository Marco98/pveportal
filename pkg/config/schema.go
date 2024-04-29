package config

import (
	"net/http"
	"net/url"
)

type YamlConfig struct {
	// direct settings
	CheckInterval uint          `yaml:"check_interval"`
	ListenPort    uint16        `yaml:"listen_port"`
	Clusters      []YamlCluster `yaml:"clusters"`
	// inheritable
	IgnoreCert   *bool  `yaml:"ignore_cert"`
	HideRepowarn *bool  `yaml:"hide_repowarn"`
	Username     string `yaml:"username"`
	Password     string `yaml:"password"`
}

type YamlCluster struct {
	// direct settings
	Name  string     `yaml:"name"`
	Hosts []YamlHost `yaml:"hosts"`
	// inheritable
	IgnoreCert   *bool  `yaml:"ignore_cert"`
	HideRepowarn *bool  `yaml:"hide_repowarn"`
	Username     string `yaml:"username"`
	Password     string `yaml:"password"`
}

type YamlHost struct {
	// direct settings
	Name     string `yaml:"name"`
	Endpoint string `yaml:"endpoint"`
	// inheritable
	IgnoreCert   *bool  `yaml:"ignore_cert"`
	HideRepowarn *bool  `yaml:"hide_repowarn"`
	Username     string `yaml:"username"`
	Password     string `yaml:"password"`
}

type Config struct {
	CheckInterval uint
	ListenPort    uint16
	Clusters      []Cluster
}

type Cluster struct {
	Name  string
	Hosts []Host
}

type Host struct {
	Name         string
	Endpoint     *url.URL
	IgnoreCert   bool
	HideRepowarn bool
	Username     string
	Password     string
	Online       bool
	Client       *http.Client
}
