package config

type Config struct {
	// KafkaBrokers is a list of kafka brokers
	Brokers string `default:"localhost:9092" env:"KAFKA_BROKERS"`

	// The Kafka topic to which messages are published or from which they are consumed.
	Topic string `default:"temperature.fetch.trigger" env:"KAFKA_TOPIC"`

	Username string `env:"KAFKA_USERNAME"`
	Password string `env:"KAFKA_PASSWORD"`

	// SASLMechanism is the mechanism used for SASL authentication.
	SASLMechanism string `default:"" env:"KAFKA_SASL_MECHANISM"`

	// Set to SSL or SASL_SSL for TLS
	SecurityProtocol string `default:"PLAINTEXT" env:"KAFKA_SECURITY_PROTOCOL"`

	// Path to the CA certificate (used to validate the server certificate). CA cert (PEM)
	Ca string `env:"KAFKA_CA"`

	// Disables cert validation if false
	TlsVerify string `default:"true" env:"KAFKA_TLS_VERIFY"`

	// Path to the client certificate (used for mTLS auth). Client cert (PEM
	ClientCert string `env:"KAFKA_CLIENT_CERT"`

	// Path to the client private key. Private key (PEM)
	ClientKey string `env:"KAFKA_CLIENT_KEY"`
}
