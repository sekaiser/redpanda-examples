package auth

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/sekaiser/redpanda-examples/internal/config"
	"github.com/sekaiser/redpanda-examples/internal/sasl"
	"github.com/twmb/franz-go/pkg/kgo"
)

type saslMechanismBuilder interface {
	name() string
	build(cfg *config.Config) (SASLMechanism, error)
}

// SASLMechanism defines an interface for SASL mechanisms to be applied
// to kgo configurations.
type SASLMechanism interface {
	KgoOpts(ctx context.Context) ([]kgo.Opt, error)
}

type saslMechanismRegistry map[string]saslMechanismBuilder

// registry is the global registry of SASL Mechanisms.
var registry saslMechanismRegistry = make(map[string]saslMechanismBuilder)

// register registers a SASL Mechanism to the global registry. It must only be
// called during init().
func (r saslMechanismRegistry) register(b saslMechanismBuilder) {
	n := b.name()
	if _, ok := r[n]; ok {
		panic("duplicate sasl mechanism registered: " + n)
	}
	r[n] = b
}

func Pick(c *config.Config) (_ SASLMechanism, ok bool, _ error) {
	return registry.pick(c)
}

// pick returns a saslMechanism for the given sink URL, or ok=false if none is specified.
func (r saslMechanismRegistry) pick(c *config.Config) (_ SASLMechanism, ok bool, _ error) {
	mechanism := c.SASLMechanism
	if mechanism == "" {
		mechanism = string(sasl.PLAIN)
	}
	b, ok := r[mechanism]
	if !ok {
		return nil, false, fmt.Errorf("param sasl_mechanism must be one of %s", r.allMechanismNames())
	}

	mech, err := b.build(c)
	if err != nil {
		return nil, false, err
	}
	return mech, true, nil
}

func (r saslMechanismRegistry) allMechanismNames() string {
	allMechanisms := make([]string, 0, len(r))
	for k := range r {
		allMechanisms = append(allMechanisms, k)
	}
	sort.Strings(allMechanisms)
	return strings.Join(allMechanisms[:len(allMechanisms)-1], ", ") +
		", or " + allMechanisms[len(allMechanisms)-1]
}
