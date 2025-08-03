package security

type Protocol string

const (
	// No TLS, no SASL
	PLAINTEXT Protocol = "PLAINTEXT"

	// TLS only, no SASL
	SSL Protocol = "SSL"

	// SASL over plaintext
	SASL_PLAINTEXT Protocol = "SASL_PLAINTEXT"

	// 	SASL over TLS
	SASL_SSL Protocol = "SASL_SSL"
)
