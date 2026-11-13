package main

import (
	"encoding/json"
	"errors"
	"os"
)

// configFile lives in the plugin folder (Zoraxy starts plugins with their own
// folder as working directory). It is written by the UI only.
const configFile = "method-filter.json"

func loadConfig() (*Config, error) {
	c := &Config{Rules: map[string]*Rule{}}
	data, err := os.ReadFile(configFile)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(data, c); err != nil {
		return &Config{Rules: map[string]*Rule{}}, err
	}
	if err := c.Sanitize(); err != nil {
		return &Config{Rules: map[string]*Rule{}}, err
	}
	return c, nil
}

// saveConfig writes atomically, so a crash never leaves a truncated file.
func saveConfig(c *Config) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := configFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, configFile)
}
