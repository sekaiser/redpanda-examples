package tls

import (
	"encoding/json"
	"fmt"
	"strings"
)

type Config struct {
	Name              string `json:"name,omitempty"`
	Enabled           bool   `json:"enabled"`
	RequireClientAuth bool   `json:"require_client_auth"`
	CertFile          string `json:"cert_file,omitempty"`
	KeyFile           string `json:"key_file,omitempty"`
	TruststoreFile    string `json:"truststore_file,omitempty"`
}

func (c Config) JSONString() string {
	data, err := json.Marshal(c)
	if err != nil {
		fmt.Println(err)
		return ""
	}
	return string(data)
}

func BuildTlsConfigString(cfgs ...Config) string {
	cfgStrings := make([]string, len(cfgs))
	for i := range cfgs {
		cfgStrings[i] = cfgs[i].JSONString()
	}

	return strings.Join(cfgStrings, ",")
}

// BuildKafkaApiTlsString returns a `--set` string for kafka_api_tls config
func BuildKafkaApiTlsString(cfgs ...Config) string {
	if len(cfgs) == 0 {
		return ""
	}

	cfgStrings := BuildTlsConfigString(cfgs...)

	return fmt.Sprintf(`redpanda.kafka_api_tls=[%s]`, cfgStrings)
}
