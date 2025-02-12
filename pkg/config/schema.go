package config

import (
	"net/url"
	"time"
)

type YamlConfig struct {
	// direct settings
	CheckInterval          *int          `yaml:"check_interval"`
	ListenPort             uint16        `yaml:"listen_port"`
	TLSCertFile            string        `yaml:"tls_cert_file"`
	TLSKeyFile             string        `yaml:"tls_key_file"`
	TLSIgnoreCert          *bool         `yaml:"tls_ignore_cert"`
	ServerTimeoutWrite     *int          `yaml:"server_timeout_write"`
	ServerTimeoutRead      *int          `yaml:"server_timeout_read"`
	Clusters               []YamlCluster `yaml:"clusters"`
	PassthroughAuth        *bool         `yaml:"passthroughauth"`
	PassthroughAuthMaxfail *int          `yaml:"passthroughauth_maxfail"`
	SessionTime            string        `yaml:"sessiontime"`
	HstsEnabled            bool          `yaml:"hsts"`
	// inheritable
	HideRepowarn *bool  `yaml:"hide_repowarn"`
	Username     string `yaml:"username"`
	Password     string `yaml:"password"`
}

type YamlCluster struct {
	// direct settings
	Name  string     `yaml:"name"`
	Hosts []YamlHost `yaml:"hosts"`
	// inheritable
	HideRepowarn *bool  `yaml:"hide_repowarn"`
	Username     string `yaml:"username"`
	Password     string `yaml:"password"`
}

type YamlHost struct {
	// direct settings
	Name     string `yaml:"name"`
	Endpoint string `yaml:"endpoint"`
	// inheritable
	HideRepowarn *bool  `yaml:"hide_repowarn"`
	Username     string `yaml:"username"`
	Password     string `yaml:"password"`
}

type Config struct {
	CheckInterval          int
	ListenPort             uint16
	PassthroughAuth        bool
	PassthroughAuthMaxfail int
	SessionTime            time.Duration
	TLSCertFile            string
	TLSKeyFile             string
	TLSIgnoreCert          bool
	Clusters               []Cluster
	ServerTimeoutWrite     int
	ServerTimeoutRead      int
	HstsEnabled            bool
}

type Cluster struct {
	Name  string
	Hosts []Host
}

type Host struct {
	Name         string
	Endpoint     *url.URL
	HideRepowarn bool
	Username     string
	Password     string
	Online       bool
}
