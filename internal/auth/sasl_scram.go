package auth

import (
	"context"
	"fmt"

	"github.com/sekaiser/redpanda-examples/internal/config"
	mechanism "github.com/sekaiser/redpanda-examples/internal/sasl"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl"
	kgosaslscram "github.com/twmb/franz-go/pkg/sasl/scram"
)

type saslSCRAMSHA256Builder struct{}

// name implements authMechanismBuilder.
func (s saslSCRAMSHA256Builder) name() string {
	return string(mechanism.SASLTypeSCRAMSHA256)
}

// build implements authMechanismBuilder.
func (s saslSCRAMSHA256Builder) build(c *config.Config) (SASLMechanism, error) {
	return &saslSCRAMSHA{
		user:     c.Username,
		password: c.Password,
		depth:    shaDepth256,
	}, nil
}

type shaDepth int

const (
	shaDepth256 shaDepth = 256
	shaDepth512 shaDepth = 512
)

type saslSCRAMSHA struct {
	depth    shaDepth
	user     string
	password string
}

// KgoOpts implements AuthMechanism.
func (s *saslSCRAMSHA) KgoOpts(ctx context.Context) ([]kgo.Opt, error) {
	var mechFn func(func(ctx context.Context) (kgosaslscram.Auth, error)) sasl.Mechanism
	switch s.depth {
	case shaDepth256:
		mechFn = kgosaslscram.Sha256
	case shaDepth512:
		mechFn = kgosaslscram.Sha512
	default:
		return nil, fmt.Errorf("unknown SCRAM SHA depth %d", s.depth)
	}

	mech := mechFn(func(ctc context.Context) (kgosaslscram.Auth, error) {
		return kgosaslscram.Auth{
			User: s.user,
			Pass: s.password,
		}, nil
	})

	return []kgo.Opt{
		kgo.SASL(mech),
	}, nil
}

var _ saslMechanismBuilder = saslSCRAMSHA256Builder{}

type saslSCRAMSHA512Builder struct{}

// name implements authMechanismBuilder.
func (s saslSCRAMSHA512Builder) name() string {
	return string(mechanism.SASLTypeSCRAMSHA512)
}

// build implements authMechanismBuilder.
func (s saslSCRAMSHA512Builder) build(c *config.Config) (SASLMechanism, error) {
	return &saslSCRAMSHA{
		user:     c.Username,
		password: c.Password,
		depth:    shaDepth512,
	}, nil
}

var _ SASLMechanism = (*saslSCRAMSHA)(nil)

func init() {
	registry.register(saslSCRAMSHA256Builder{})
	registry.register(saslSCRAMSHA512Builder{})
}
