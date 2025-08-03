package config

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/sekaiser/redpanda-examples/internal/sasl"
	"github.com/sekaiser/redpanda-examples/internal/testutil/config/api"
	"github.com/sekaiser/redpanda-examples/internal/testutil/config/tls"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

type cmdTag struct{}
type execTag struct{}
type certTag struct{}

type Option[T any] struct {
	apply func(*configBuilder)
}

func CmdOption(f func(*configBuilder)) Option[cmdTag] {
	return Option[cmdTag]{apply: f}
}

func ExecOption(f func(*configBuilder)) Option[execTag] {
	return Option[execTag]{apply: f}
}

func CertOption(f func(*configBuilder)) Option[certTag] {
	return Option[certTag]{apply: f}
}

type Container struct {
	Container testcontainers.Container
	Endpoint  string
}

type ContainerBuilder interface {
	WithCmd(...Option[cmdTag]) ContainerBuilder
	WithExecs(...Option[execTag]) ContainerBuilder
	WithDirs(...Option[certTag]) ContainerBuilder
	Build(ctx context.Context) (*Container, error)
}

type configBuilder struct {
	cmd        []string
	exec       [][]string
	srcDirs    []string
	targetDirs []string
}

func NewBuilder() (builder ContainerBuilder) {
	builder = &configBuilder{
		cmd:        []string{"redpanda", "start", "--overprovisioned", "--smp", "1", "--check=false"},
		srcDirs:    []string{},
		targetDirs: []string{},
	}
	return
}

func (b *configBuilder) WithCmd(opts ...Option[cmdTag]) ContainerBuilder {
	return applyOptions(b, opts...)
}

func (b *configBuilder) WithExecs(opts ...Option[execTag]) ContainerBuilder {
	return applyOptions(b, opts...)
}

func (b *configBuilder) WithDirs(opts ...Option[certTag]) ContainerBuilder {
	return applyOptions(b, opts...)
}

func (b *configBuilder) Build(ctx context.Context) (*Container, error) {
	req := testcontainers.ContainerRequest{
		Image:        "redpandadata/redpanda:v25.1.8",
		ExposedPorts: []string{"9092/tcp", "9644/tcp"},
		WaitingFor: wait.ForHTTP("/v1/status/ready").
			WithPort("9644/tcp").
			WithStartupTimeout(60 * time.Second),
		Cmd: b.cmd,
	}

	if len(b.srcDirs) > 0 {
		mounts := make([]testcontainers.ContainerMount, len(b.srcDirs))
		for i, cert := range b.srcDirs {
			mounts[i] = testcontainers.BindMount(cert, testcontainers.ContainerMountTarget(b.targetDirs[i]))
		}

		req.Mounts = testcontainers.Mounts(mounts[0])
	}

	kafkaC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, err
	}

	host, err := kafkaC.Host(ctx)
	if err != nil {
		return nil, err
	}
	port, err := kafkaC.MappedPort(ctx, "9092")
	if err != nil {
		return nil, err
	}

	for _, exec := range b.exec {
		_, _, err = kafkaC.Exec(ctx, exec)
		if err != nil {
			return nil, err
		}
	}

	endpoint := fmt.Sprintf("%s:%s", host, port.Port())
	return &Container{
		Container: kafkaC,
		Endpoint:  endpoint,
	}, nil
}

func applyOptions[T any](b *configBuilder, opts ...Option[T]) ContainerBuilder {
	for _, opt := range opts {
		opt.apply(b)
	}
	return b
}

func WithDir(srcDir, targetDir string) Option[certTag] {
	return CertOption(func(b *configBuilder) {
		b.srcDirs = append(b.srcDirs, srcDir)
		b.targetDirs = append(b.targetDirs, targetDir)
	})
}

func WithMemory(mem string) Option[cmdTag] {
	return CmdOption(func(b *configBuilder) {
		b.cmd = append(b.cmd, "--memory", mem)
	})
}

func WithSmp(smp int) Option[cmdTag] {
	return CmdOption(func(b *configBuilder) {
		b.cmd = append(b.cmd, "--smp", strconv.Itoa(smp))
	})
}

func WithKafkaAddr(name, listen, advertise string) Option[cmdTag] {
	return CmdOption(func(b *configBuilder) {
		b.cmd = append(b.cmd,
			fmt.Sprintf("--kafka-addr %s://%s", name, listen),
			fmt.Sprintf("--advertise-kafka-addr %s://%s", name, advertise),
		)
	})
}

func WithKafkaTLS(cfgs ...tls.Config) Option[cmdTag] {
	return CmdOption(func(b *configBuilder) {
		b.cmd = append(b.cmd, "--set", tls.BuildKafkaApiTlsString(cfgs...))
	})
}

func WithDefaultSasl() Option[cmdTag] {
	cfg := api.Config{
		Address:              "0.0.0.0",
		Port:                 "9092",
		AuthenticationMethod: "sasl",
	}
	return CmdOption(func(b *configBuilder) {
		WithKafkaApi(cfg).apply(b)
		WithSasl().apply(b)
	})
}

func WithSasl() Option[cmdTag] {
	return CmdOption(func(b *configBuilder) {
		b.cmd = append(b.cmd, "--set redpanda.enable_sasl=true")
	})
}

func WithKafkaApi(cfgs ...api.Config) Option[cmdTag] {
	return CmdOption(func(b *configBuilder) {
		b.cmd = append(b.cmd, "--set", api.BuildKafkaApiString(cfgs...))
	})
}

func WithSaslMechanims(ms ...sasl.Mechanism) Option[execTag] {
	return ExecOption(func(b *configBuilder) {
		parts := make([]string, len(ms))

		for i := range ms {
			if ms[i] == sasl.SASLTypeSCRAMSHA256 || ms[i] == sasl.SASLTypeSCRAMSHA512 {
				parts[i] = "\"SCRAM\""
			} else if ms[i] == sasl.PLAIN {
				parts[i] = "\"PLAIN\""
				parts = append(parts, "\"SCRAM\"")
			}

		}
		exec := []string{"rpk", "cluster", "config", "set", "sasl_mechanisms", fmt.Sprintf("[%s]", strings.Join(parts, ","))}
		b.exec = append(b.exec, exec)
	})
}

func WithSaslUsers(users ...User) Option[execTag] {
	return ExecOption(func(b *configBuilder) {
		parts := make([][]string, len(users))

		for i := range users {
			username := users[i].Username
			password := users[i].Password
			mechanism := users[i].Mechanism
			parts[i] = []string{"rpk", "acl", "user", "create", username, "-p", password, "--mechanism", mechanism}
		}

		b.exec = append(b.exec, parts...)
	})
}
