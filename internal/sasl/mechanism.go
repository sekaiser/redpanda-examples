package sasl

type Mechanism string

const (
	// SASL over plaintext: Username & password, simplest
	PLAIN Mechanism = "PLAIN"

	// SASL over TLS represents the SCRAM-SHA-256 mechanism.
	SASLTypeSCRAMSHA256 Mechanism = "SCRAM-SHA-256"

	// SASL over TLS represents the SCRAM-SHA-512 mechanism.
	SASLTypeSCRAMSHA512 Mechanism = "SCRAM-SHA-512"
)
