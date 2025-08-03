package tls

import (
	"testing"
)

func TestConfig_JSONString(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		want    string
		wantErr bool
	}{
		// {
		// 	name: "basic config",
		// 	config: Config{
		// 		Name:    "test",
		// 		Enabled: true,
		// 	},
		// 	want: `{"name":"test","enabled":true}`,
		// },
		{
			name: "tls config",
			config: Config{
				Name:              "OUTSIDE",
				Enabled:           true,
				RequireClientAuth: false,
				CertFile:          "cert.pem",
				KeyFile:           "key.pem",
				TruststoreFile:    "ca.pem",
			},
			want: `{"name":"OUTSIDE","enabled":true,"require_client_auth":false,"cert_file":"cert.pem","key_file":"key.pem","truststore_file":"ca.pem"}`,
		},
		// {
		// 	name: "config with omitempty fields empty",
		// 	config: Config{
		// 		Name:    "empty_omitempty",
		// 		Enabled: false,
		// 	},
		// 	want: `{"name":"empty_omitempty","enabled":false}`,
		// },
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.JSONString()
			if got != tt.want {
				t.Errorf("TLSConfig.JSONString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBuildConfigString(t *testing.T) {
	tests := []struct {
		name string
		cfgs []Config
		want string
	}{
		{
			name: "single config",
			cfgs: []Config{
				{Name: "test1", Enabled: true},
			},
			want: `{"name":"test1","enabled":true}`,
		},
		{
			name: "multiple configs",
			cfgs: []Config{
				{Name: "test1", Enabled: true},
				{Name: "test2", Enabled: false, CertFile: "cert2.pem"},
			},
			want: `{"name":"test1","enabled":true},{"name":"test2","enabled":false,"cert_file":"cert2.pem"}`,
		},
		{
			name: "no configs",
			cfgs: []Config{},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildTlsConfigString(tt.cfgs...)
			if got != tt.want {
				t.Errorf("BuildTlsConfigString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBuildKafkaApiTlsString(t *testing.T) {
	tests := []struct {
		name string
		cfgs []Config
		want string
	}{
		{
			name: "single config",
			cfgs: []Config{
				{Name: "kafka1", Enabled: true},
			},
			want: `redpanda.kafka_api_tls=[{"name":"kafka1","enabled":true}]`,
		},
		{
			name: "multiple configs",
			cfgs: []Config{
				{Name: "kafka1", Enabled: true},
				{Name: "kafka2", Enabled: false, KeyFile: "key2.pem"},
			},
			want: `redpanda.kafka_api_tls=[{"name":"kafka1","enabled":true},{"name":"kafka2","enabled":false,"key_file":"key2.pem"}]`,
		},
		{
			name: "no configs",
			cfgs: []Config{},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildKafkaApiTlsString(tt.cfgs...)
			if got != tt.want {
				t.Errorf("BuildKafkaApiTlsString() = %v, want %v", got, tt.want)
			}
		})
	}
}
