package main

import (
	"fmt"
	"os"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

type Config struct {
	location   string
	ListenAddr string      `yaml:"listen_addr"`
	Proxy      ProxyConfig `yaml:"proxy"`
}

type ProxyConfig struct {
	Services []ServiceConfig `yaml:"services"`
	Dns      string          `yaml:"dns"`
}

type ServiceConfig struct {
	BindAddr string       `yaml:"bind_addr"`
	Proto    string       `yaml:"proto"`
	Peers    []PeerConfig `yaml:"peers"`
}

type PeerConfig struct {
	ID             uuid.UUID `yaml:"id"`
	UserName       string    `yaml:"username"`
	Password       string    `yaml:"password"`
	MaxConnections uint      `yaml:"max_connections"`
	FramedIP       string    `yaml:"framed_ip"`
	RxRate         uint32    `yaml:"rx_rate"`
	TxRate         uint32    `yaml:"tx_rate"`
	Disabled       bool      `yaml:"disabled"`
}

func FindConfigLocation() string {

	entries := []string{
		"./nx-auth.yaml",
		"./nx-auth.yml",
		"./testing/cmd/nx-auth/nx-auth.yaml",
		"./testing/cmd/nx-auth/nx-auth.yml",
	}

	var findFile = func(name string) bool {
		_, err := os.Stat(name)
		return err == nil
	}

	var loc string
	for _, name := range entries {
		if ok := findFile(name); ok {
			loc = name
			break
		}
	}

	return loc
}

func LoadConfig(loc string) (*Config, error) {

	if loc == "" {
		loc = FindConfigLocation()
	}

	if loc == "" {
		return nil, fmt.Errorf("no config files found on the system")
	}

	file, err := os.Open(loc)
	if err != nil {
		return nil, err
	}

	defer file.Close()

	var cfg Config
	if err := yaml.NewDecoder(file).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config: %v", err)
	}

	cfg.location = loc

	return &cfg, nil
}
