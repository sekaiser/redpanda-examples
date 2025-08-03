package testutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func GenerateTestCerts(t *testing.T, parentDir string) string {
	t.Helper()

	certDir := filepath.Join(parentDir, "certs")
	err := os.MkdirAll(certDir, 0755)
	require.NoError(t, err, "failed to create cert directory")

	// --- 1. Generate CA cert + key ---
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "failed to generate CA key")

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Test CA"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPrivKey.PublicKey, caPrivKey)
	require.NoError(t, err, "failed to create CA cert")

	writePEM(t, filepath.Join(certDir, "ca.pem"), "CERTIFICATE", caDER)
	writePEM(t, filepath.Join(certDir, "ca-key.pem"), "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(caPrivKey))

	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err, "failed to parse CA cert")

	// --- 2. Generate server cert + key ---
	serverPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "failed to generate server key")

	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{Organization: []string{"Test Server"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", "redpanda"},
		IPAddresses: []net.IP{
			net.ParseIP("127.0.0.1"),
		},
		BasicConstraintsValid: true,
	}

	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverPrivKey.PublicKey, caPrivKey)
	require.NoError(t, err, "failed to create server cert")

	writePEM(t, filepath.Join(certDir, "cert.pem"), "CERTIFICATE", serverDER)
	writePEM(t, filepath.Join(certDir, "key.pem"), "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(serverPrivKey))

	// --- 3. Generate client cert + key ---
	clientPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "failed to generate client key")

	clientTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{Organization: []string{"Test Client"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientPrivKey.PublicKey, caPrivKey)
	require.NoError(t, err, "failed to create client cert")

	writePEM(t, filepath.Join(certDir, "client-cert.pem"), "CERTIFICATE", clientDER)
	writePEM(t, filepath.Join(certDir, "client-key.pem"), "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(clientPrivKey))

	return certDir
}

func writePEM(t *testing.T, path, typ string, derBytes []byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("failed to create %s: %v", path, err)
	}
	defer f.Close()

	err = pem.Encode(f, &pem.Block{Type: typ, Bytes: derBytes})
	if err != nil {
		t.Fatalf("failed to write %s: %v", path, err)
	}
}
