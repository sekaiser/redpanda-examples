package api

import (
	"encoding/json"
	"fmt"
	"strings"
)

type Config struct {
	Name                 string `json:"name,omitempty"`
	Address              string `json:"address"`
	Port                 string `json:"port"`
	AuthenticationMethod string `json:"authentication_method"`
}

func (c Config) JSONString() string {
	data, err := json.Marshal(c)
	if err != nil {
		fmt.Println(err)
		return ""
	}
	return string(data)
}

func BuildConfigString(cfgs ...Config) string {
	cfgStrings := make([]string, len(cfgs))
	for i := range cfgs {
		cfgStrings[i] = cfgs[i].JSONString()
	}

	return strings.Join(cfgStrings, ",")
}

// BuildKafkaApiString returns a `--set` string for kafka_api config
func BuildKafkaApiString(cfgs ...Config) string {
	if len(cfgs) == 0 {
		return ""
	}

	cfgStrings := BuildConfigString(cfgs...)

	return fmt.Sprintf(`redpanda.kafka_api=[%s]`, cfgStrings)
}
