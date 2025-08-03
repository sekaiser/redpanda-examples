package redpandaexamples

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/sekaiser/redpanda-examples/internal/auth"
	"github.com/sekaiser/redpanda-examples/internal/config"
	"github.com/sekaiser/redpanda-examples/internal/security"
	"github.com/twmb/franz-go/pkg/kgo"
)

func BuildKgoConfig(
	ctx context.Context,
	cfg *config.Config,
) ([]kgo.Opt, error) {
	var opts []kgo.Opt

	dialConfig, err := buildDialConfig(cfg)
	if err != nil {
		return nil, err
	}

	if dialConfig.tlsEnabled {
		tlsCfg := &tls.Config{InsecureSkipVerify: dialConfig.tlsSkipVerify, MinVersion: tls.VersionTLS12}
		if dialConfig.caCert != nil {
			caCertPool, err := x509.SystemCertPool()
			if err != nil {
				return nil, errors.Join(err, errors.New("could not load system root CA pool"))
			}
			if caCertPool == nil {
				caCertPool = x509.NewCertPool()
			}
			caCertPool.AppendCertsFromPEM(dialConfig.caCert)
			tlsCfg.RootCAs = caCertPool
		}

		if dialConfig.clientCert != nil && dialConfig.clientKey == nil {
			return nil, fmt.Errorf(`%s requires %s to be set`, "KAFKA_CLIENT_CERT", "KAFKA_CLIENT_KEY")
		} else if dialConfig.clientKey != nil && dialConfig.clientCert == nil {
			return nil, fmt.Errorf(`%s requires %s to be set`, "KAFKA_CLIENT_KEY", "KAFKA_CLIENT_CERT")
		}

		if dialConfig.clientCert != nil && dialConfig.clientKey != nil {
			cert, err := tls.X509KeyPair(dialConfig.clientCert, dialConfig.clientKey)
			if err != nil {
				return nil, errors.Join(err, errors.New(`invalid client certificate data provided`))
			}
			tlsCfg.Certificates = []tls.Certificate{cert}
		}

		// The 10s dial timeout is the default in kgo if you don't manually
		// specify a Dialer. Since we are creating one we want to match the
		// default behavior. See kgo.NewClient.
		dialer := &net.Dialer{Timeout: 10 * time.Second}
		tlsDialer := &tls.Dialer{NetDialer: dialer, Config: tlsCfg}
		opts = append(opts, kgo.Dialer(tlsDialer.DialContext))
	} else {
		if dialConfig.caCert != nil {
			return nil, fmt.Errorf(`%s requires %s`, "KAFKA_CA", "tls is enabled")
		}
		if dialConfig.clientCert != nil {
			return nil, fmt.Errorf(`%s requires %s`, "KAFKA_CLIENT_CERT", "tls is enabled")
		}
		// The 10s dial timeout is the default in kgo if you don't manually
		// specify a Dialer. Since we are creating one we want to match the
		// default behavior. See kgo.NewClient.
		dialer := &net.Dialer{Timeout: 10 * time.Second}
		opts = append(opts, kgo.Dialer(dialer.DialContext))
	}

	if dialConfig.authMechanism != nil {
		authOpts, err := dialConfig.authMechanism.KgoOpts(ctx)
		if err != nil {
			return nil, err
		}
		opts = append(opts, authOpts...)
	}

	if cfg.Brokers == "" {
		return nil, fmt.Errorf(`%s must be set`, "KAFKA_BROKERS")
	}
	brokerList := strings.Split(cfg.Brokers, ",")
	if len(brokerList) == 0 {
		return nil, fmt.Errorf(`%s must not be empty`, "KAFKA_BROKERS")
	}
	for _, broker := range brokerList {
		if broker == "" {
			return nil, fmt.Errorf(`%s must not contain empty broker addresses`, "KAFKA_BROKERS")
		}
	}

	opts = append(opts, kgo.SeedBrokers(brokerList...))

	return opts, nil
}

type kafkaDialConfig struct {
	tlsEnabled    bool
	tlsSkipVerify bool
	caCert        []byte
	clientCert    []byte
	clientKey     []byte
	authMechanism auth.SASLMechanism
}

func buildDialConfig(cfg *config.Config) (*kafkaDialConfig, error) {
	dialConfig := kafkaDialConfig{}

	securityProtocol := strings.ToUpper(cfg.SecurityProtocol)

	if securityProtocol == string(security.PLAINTEXT) && cfg.SASLMechanism != "" {
		return nil, fmt.Errorf(`%s cannot be set when %s is %s`,
			"KAFKA_SASL_MECHANISM", "KAFKA_SECURITY_PROTOCOL", security.PLAINTEXT)
	}

	if securityProtocol == string(security.SSL) && cfg.SASLMechanism != "" {
		return nil, fmt.Errorf(`%s cannot be set when %s is %s`,
			"KAFKA_SASL_MECHANISM", "KAFKA_SECURITY_PROTOCOL", security.SSL)
	}

	dialConfig.tlsEnabled = securityProtocol == string(security.SSL) || securityProtocol == string(security.SASL_SSL)
	dialConfig.tlsSkipVerify = strings.ToLower(cfg.TlsVerify) == "false" || cfg.TlsVerify == "0"

	if cfg.Ca != "" {
		caBytes, err := os.ReadFile(cfg.Ca)
		if err != nil {
			return nil, fmt.Errorf("reading CA: %w", err)
		}
		dialConfig.caCert = caBytes
	}

	if cfg.ClientCert != "" {
		caBytes, err := os.ReadFile(cfg.ClientCert)
		if err != nil {
			return nil, fmt.Errorf("reading CA: %w", err)
		}
		dialConfig.clientCert = caBytes
	}

	if cfg.ClientKey != "" {
		keyPEM, err := os.ReadFile(cfg.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("reading CA: %w", err)
		}
		dialConfig.clientKey = keyPEM
	}

	if securityProtocol == string(security.SASL_PLAINTEXT) || securityProtocol == string(security.SASL_SSL) {
		authMechanism, ok, err := auth.Pick(cfg)
		if err != nil {
			return nil, err
		}
		if ok {
			dialConfig.authMechanism = authMechanism
		}
	}

	return &dialConfig, nil
}
