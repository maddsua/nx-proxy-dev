package main

import (
	"bufio"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
)

type ConfigEntries map[string]string

func LoadConfigFile() (ConfigEntries, string) {

	entries := []string{
		"/etc/nx-proxy/nx-proxy.conf",
		"~/nx-proxy.conf",
		"./nx-proxy.conf",
	}

	var parseProperty = func(line string) (string, string, bool) {

		key, val, has := strings.Cut(line, "=")
		if !has {
			return "", "", false
		}

		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)

		if key == "" || key[0] == '#' || val == "" {
			return "", "", false
		}

		return strings.ToUpper(key), val, true
	}

	var readContents = func(name string) (ConfigEntries, error) {

		file, err := os.Open(name)
		if err != nil {
			return nil, err
		}

		defer file.Close()

		entries := ConfigEntries{}

		scanner := bufio.NewScanner(file)

		for scanner.Scan() {

			key, val, ok := parseProperty(scanner.Text())
			if ok {
				entries[key] = val
			}
		}

		return entries, scanner.Err()
	}

	for _, name := range entries {
		if val, err := readContents(name); err == nil {
			return val, name
		}
	}

	return nil, ""
}

func GetConfigOpt(fileEntries ConfigEntries, name string) (string, bool) {

	name = strings.ToUpper(name)

	var getEnv = func() string {
		return os.Getenv("NXPROXY_" + name)
	}

	if val := getEnv(); val != "" {
		return val, true
	}

	if fileEntries != nil {
		if val, has := fileEntries[name]; has {
			return val, true
		}
	}

	return "", false
}

func ParseAuthUrl(val string) (*url.URL, error) {

	url, err := url.Parse(val)
	if err != nil {
		return nil, err
	}

	switch url.Scheme {
	case "http", "https":
		break
	default:
		return nil, fmt.Errorf("invalid url scheme: %s", url.Scheme)
	}

	if url.Host == "" {
		return nil, errors.New("invalid url host")
	}

	return url, nil
}
