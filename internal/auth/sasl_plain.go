package auth

import (
	"context"

	"github.com/sekaiser/redpanda-examples/internal/config"
	"github.com/sekaiser/redpanda-examples/internal/sasl"
	"github.com/twmb/franz-go/pkg/kgo"
	kgosaslplain "github.com/twmb/franz-go/pkg/sasl/plain"
)

type saslPlainBuilder struct{}

// name implements authMechanismBuilder.
func (s saslPlainBuilder) name() string {
	return string(sasl.PLAIN)
}

func (s saslPlainBuilder) build(c *config.Config) (SASLMechanism, error) {
	return &saslPlain{
		user:     c.Username,
		password: c.Password,
	}, nil
}

var _ saslMechanismBuilder = saslPlainBuilder{}

type saslPlain struct {
	user     string
	password string
}

// KgoOpts implements AuthMechanism.
func (s *saslPlain) KgoOpts(ctx context.Context) ([]kgo.Opt, error) {
	mech := kgosaslplain.Plain(func(ctc context.Context) (kgosaslplain.Auth, error) {
		return kgosaslplain.Auth{
			User: s.user,
			Pass: s.password,
		}, nil
	})

	return []kgo.Opt{
		kgo.SASL(mech),
	}, nil
}

var _ SASLMechanism = (*saslPlain)(nil)

func init() {
	registry.register(saslPlainBuilder{})
}
