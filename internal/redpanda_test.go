package redpandaexamples

import (
	"context"
	"os"
	"testing"
	"time"

	cconfig "github.com/sekaiser/redpanda-examples/internal/config"
	"github.com/sekaiser/redpanda-examples/internal/sasl"
	"github.com/sekaiser/redpanda-examples/internal/testutil"
	"github.com/sekaiser/redpanda-examples/internal/testutil/config"
	"github.com/sekaiser/redpanda-examples/internal/testutil/config/api"
	"github.com/sekaiser/redpanda-examples/internal/testutil/config/tls"
	"github.com/stretchr/testify/require"
	"github.com/twmb/franz-go/pkg/kgo"
)

func Test_NoAuthNoTLS(t *testing.T) {
	ctx := context.Background()

	redpandaC, err := config.NewBuilder().
		WithCmd(config.WithMemory("512M"), config.WithKafkaApi(api.Config{
			Address: "0.0.0.0",
			Port:    "9092",
		})).
		Build(ctx)

	require.NoError(t, err)
	defer redpandaC.Container.Terminate(ctx)

	config := &cconfig.Config{
		Brokers:          redpandaC.Endpoint,
		TlsVerify:        "false",
		SecurityProtocol: "PLAINTEXT",
	}
	opts, err := BuildKgoConfig(ctx, config)
	require.NoError(t, err)
	client, err := kgo.NewClient(opts...)
	require.NoError(t, err)
	defer client.Close()

	// Confirm metadata fetch works (sanity check)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = client.Ping(ctx)
	require.NoError(t, err)
}

func Test_TLSWithoutAuth(t *testing.T) {
	path := "/tmp/colima/Test_TLSWithoutAuth"
	ctx := context.Background()
	certDir := testutil.GenerateTestCerts(t, path)
	defer func() {
		os.RemoveAll(path)
	}()

	redpandaC, err := config.NewBuilder().
		WithDirs(config.WithDir(certDir, "/etc/redpanda/certs")).
		WithCmd(config.WithMemory("512M"), config.WithKafkaTLS(tls.Config{
			CertFile:       "/etc/redpanda/certs/cert.pem",
			KeyFile:        "/etc/redpanda/certs/key.pem",
			TruststoreFile: "/etc/redpanda/certs/ca.pem",
			Enabled:        true,
		})).
		Build(ctx)

	require.NoError(t, err)
	defer redpandaC.Container.Terminate(ctx)

	config := &cconfig.Config{
		Brokers:          redpandaC.Endpoint,
		TlsVerify:        "false",
		SecurityProtocol: "SSL",
	}
	opts, err := BuildKgoConfig(ctx, config)
	require.NoError(t, err)
	client, err := kgo.NewClient(opts...)
	require.NoError(t, err)
	defer client.Close()

	// Confirm metadata fetch works (sanity check)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = client.Ping(ctx)
	require.NoError(t, err)
}

func Test_SaslOverPlaintextPlain(t *testing.T) {
	ctx := context.Background()

	redpandaC, err := config.NewBuilder().
		WithCmd(config.WithMemory("512M"),
			config.WithDefaultSasl()).
		WithExecs(config.WithSaslMechanims(sasl.PLAIN),
			config.WithSaslUsers(config.User{
				Username:  "test-user",
				Password:  "test-password",
				Mechanism: string(sasl.SASLTypeSCRAMSHA256),
			})).Build(ctx)

	require.NoError(t, err)
	defer redpandaC.Container.Terminate(ctx)

	config := &cconfig.Config{
		Brokers:          redpandaC.Endpoint,
		TlsVerify:        "false",
		SecurityProtocol: "SASL_PLAINTEXT",
		SASLMechanism:    string(sasl.PLAIN),
		Username:         "test-user",
		Password:         "test-password",
	}
	opts, err := BuildKgoConfig(ctx, config)
	require.NoError(t, err)
	client, err := kgo.NewClient(opts...)
	require.NoError(t, err)
	defer client.Close()

	// Confirm metadata fetch works (sanity check)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = client.Ping(ctx)
	require.NoError(t, err)
}

func Test_SaslOverPlaintextSCRAMSHA256(t *testing.T) {
	ctx := context.Background()

	redpandaC, err := config.NewBuilder().
		WithCmd(config.WithMemory("512M"),
			config.WithDefaultSasl(),
			config.WithKafkaApi(api.Config{
				Address:              "0.0.0.0",
				Port:                 "9092",
				AuthenticationMethod: "sasl",
			})).
		WithExecs(config.WithSaslMechanims(sasl.SASLTypeSCRAMSHA256),
			config.WithSaslUsers(config.User{
				Username:  "test-user",
				Password:  "test-password",
				Mechanism: string(sasl.SASLTypeSCRAMSHA256),
			})).Build(ctx)

	require.NoError(t, err)
	defer redpandaC.Container.Terminate(ctx)

	config := &cconfig.Config{
		Brokers:          redpandaC.Endpoint,
		TlsVerify:        "false",
		SecurityProtocol: "SASL_PLAINTEXT",
		SASLMechanism:    string(sasl.SASLTypeSCRAMSHA256),
		Username:         "test-user",
		Password:         "test-password",
	}
	opts, err := BuildKgoConfig(ctx, config)
	require.NoError(t, err)
	client, err := kgo.NewClient(opts...)
	require.NoError(t, err)
	defer client.Close()

	// Confirm metadata fetch works (sanity check)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = client.Ping(ctx)
	require.NoError(t, err)
}

func Test_SaslOverPlaintextSCRAMSHA512(t *testing.T) {
	ctx := context.Background()

	redpandaC, err := config.NewBuilder().
		WithCmd(config.WithMemory("512M"),
			config.WithDefaultSasl(),
			config.WithKafkaApi(api.Config{
				Address:              "0.0.0.0",
				Port:                 "9092",
				AuthenticationMethod: "sasl",
			})).
		WithExecs(config.WithSaslMechanims(sasl.SASLTypeSCRAMSHA512),
			config.WithSaslUsers(config.User{
				Username:  "test-user",
				Password:  "test-password",
				Mechanism: string(sasl.SASLTypeSCRAMSHA512),
			})).Build(ctx)

	require.NoError(t, err)
	defer redpandaC.Container.Terminate(ctx)

	config := &cconfig.Config{
		Brokers:          redpandaC.Endpoint,
		TlsVerify:        "false",
		SecurityProtocol: "SASL_PLAINTEXT",
		SASLMechanism:    string(sasl.SASLTypeSCRAMSHA512),
		Username:         "test-user",
		Password:         "test-password",
	}
	opts, err := BuildKgoConfig(ctx, config)
	require.NoError(t, err)
	client, err := kgo.NewClient(opts...)
	require.NoError(t, err)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = client.Ping(ctx)
	require.NoError(t, err)
}

func Test_SaslOverSslSCRAMSHA256_WithoutClientVerification(t *testing.T) {
	path := "/tmp/colima/Test_SaslOverSslSCRAMSHA256_WithoutClientVerification"
	ctx := context.Background()
	certDir := testutil.GenerateTestCerts(t, path)
	defer func() {
		os.RemoveAll(path)
	}()

	redpandaC, err := config.NewBuilder().
		WithDirs(config.WithDir(certDir, "/etc/redpanda/certs")).
		WithCmd(config.WithMemory("512M"),
			config.WithDefaultSasl(),
			config.WithKafkaTLS(tls.Config{
				CertFile:       "/etc/redpanda/certs/cert.pem",
				KeyFile:        "/etc/redpanda/certs/key.pem",
				TruststoreFile: "/etc/redpanda/certs/ca.pem",
				Enabled:        true,
			})).
		WithExecs(config.WithSaslMechanims(sasl.SASLTypeSCRAMSHA256),
			config.WithSaslUsers(config.User{
				Username:  "test-user",
				Password:  "test-password",
				Mechanism: string(sasl.SASLTypeSCRAMSHA256),
			})).Build(ctx)

	require.NoError(t, err)
	defer redpandaC.Container.Terminate(ctx)

	config := &cconfig.Config{
		Brokers:          redpandaC.Endpoint,
		TlsVerify:        "false",
		SecurityProtocol: "SASL_SSL",
		SASLMechanism:    string(sasl.SASLTypeSCRAMSHA256),
		Username:         "test-user",
		Password:         "test-password",
	}
	opts, err := BuildKgoConfig(ctx, config)
	require.NoError(t, err)
	client, err := kgo.NewClient(opts...)
	require.NoError(t, err)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = client.Ping(ctx)
	require.NoError(t, err)
}

func Test_SaslOverSslSCRAMSHA256(t *testing.T) {
	path := "/tmp/colima/Test_SaslOverSslSCRAMSHA256"
	ctx := context.Background()
	certDir := testutil.GenerateTestCerts(t, path)
	defer func() {
		os.RemoveAll(path)
	}()

	redpandaC, err := config.NewBuilder().
		WithDirs(config.WithDir(certDir, "/etc/redpanda/certs")).
		WithCmd(config.WithMemory("512M"),
			config.WithDefaultSasl(),
			config.WithKafkaTLS(tls.Config{
				CertFile:          "/etc/redpanda/certs/cert.pem",
				KeyFile:           "/etc/redpanda/certs/key.pem",
				TruststoreFile:    "/etc/redpanda/certs/ca.pem",
				RequireClientAuth: false,
				Enabled:           true,
			})).
		WithExecs(config.WithSaslMechanims(sasl.SASLTypeSCRAMSHA256),
			config.WithSaslUsers(config.User{
				Username:  "test-user",
				Password:  "test-password",
				Mechanism: string(sasl.SASLTypeSCRAMSHA256),
			})).Build(ctx)

	require.NoError(t, err)
	defer redpandaC.Container.Terminate(ctx)

	config := &cconfig.Config{
		Brokers:          redpandaC.Endpoint,
		TlsVerify:        "true",
		SecurityProtocol: "SASL_SSL",
		SASLMechanism:    string(sasl.SASLTypeSCRAMSHA256),
		Username:         "test-user",
		Password:         "test-password",
		Ca:               certDir + "/ca.pem",
		ClientKey:        certDir + "/client-key.pem",
		ClientCert:       certDir + "/client-cert.pem",
	}
	opts, err := BuildKgoConfig(ctx, config)
	require.NoError(t, err)
	client, err := kgo.NewClient(opts...)
	require.NoError(t, err)
	defer client.Close()

	// Confirm metadata fetch works (sanity check)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = client.Ping(ctx)
	require.NoError(t, err)
}

func Test_SaslOverSslSCRAMSHA512(t *testing.T) {
	path := "/tmp/colima/Test_SaslOverSslSCRAMSHA512"
	ctx := context.Background()
	certDir := testutil.GenerateTestCerts(t, path)
	defer func() {
		os.RemoveAll(path)
	}()

	redpandaC, err := config.NewBuilder().
		WithDirs(config.WithDir(certDir, "/etc/redpanda/certs")).
		WithCmd(config.WithMemory("512M"),
			config.WithDefaultSasl(),
			config.WithKafkaTLS(tls.Config{
				CertFile:          "/etc/redpanda/certs/cert.pem",
				KeyFile:           "/etc/redpanda/certs/key.pem",
				TruststoreFile:    "/etc/redpanda/certs/ca.pem",
				RequireClientAuth: false,
				Enabled:           true,
			})).
		WithExecs(config.WithSaslMechanims(sasl.SASLTypeSCRAMSHA512),
			config.WithSaslUsers(config.User{
				Username:  "test-user",
				Password:  "test-password",
				Mechanism: string(sasl.SASLTypeSCRAMSHA512),
			})).Build(ctx)

	require.NoError(t, err)
	defer redpandaC.Container.Terminate(ctx)

	config := &cconfig.Config{
		Brokers:          redpandaC.Endpoint,
		TlsVerify:        "true",
		SecurityProtocol: "SASL_SSL",
		SASLMechanism:    string(sasl.SASLTypeSCRAMSHA512),
		Username:         "test-user",
		Password:         "test-password",
		Ca:               certDir + "/ca.pem",
		ClientKey:        certDir + "/client-key.pem",
		ClientCert:       certDir + "/client-cert.pem",
	}
	opts, err := BuildKgoConfig(ctx, config)
	require.NoError(t, err)
	client, err := kgo.NewClient(opts...)
	require.NoError(t, err)
	defer client.Close()

	// Confirm metadata fetch works (sanity check)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = client.Ping(ctx)
	require.NoError(t, err)
}

func Test_mTls(t *testing.T) {
	path := "/tmp/colima/Test_mTls"
	ctx := context.Background()
	certDir := testutil.GenerateTestCerts(t, path)
	defer func() {
		os.RemoveAll(path)
	}()

	redpandaC, err := config.NewBuilder().
		WithDirs(config.WithDir(certDir, "/etc/redpanda/certs")).
		WithCmd(config.WithMemory("512M"),
			config.WithKafkaApi(api.Config{
				Name:                 "mtls_listener",
				Address:              "0.0.0.0",
				Port:                 "9092",
				AuthenticationMethod: "mtls_identity",
			}),
			config.WithKafkaTLS(tls.Config{
				Name:              "mtls_listener",
				CertFile:          "/etc/redpanda/certs/cert.pem",
				KeyFile:           "/etc/redpanda/certs/key.pem",
				TruststoreFile:    "/etc/redpanda/certs/ca.pem",
				RequireClientAuth: true,
				Enabled:           true,
			})).Build(ctx)

	require.NoError(t, err)
	defer redpandaC.Container.Terminate(ctx)

	config := &cconfig.Config{
		Brokers:          redpandaC.Endpoint,
		TlsVerify:        "false",
		SecurityProtocol: "SSL",
		Ca:               certDir + "/ca.pem",
		ClientKey:        certDir + "/client-key.pem",
		ClientCert:       certDir + "/client-cert.pem",
	}
	opts, err := BuildKgoConfig(ctx, config)
	require.NoError(t, err)
	client, err := kgo.NewClient(opts...)
	require.NoError(t, err)
	defer client.Close()

	// Confirm metadata fetch works (sanity check)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = client.Ping(ctx)
	require.NoError(t, err)
}
