package x509wrapper

import (
	"crypto/x509/pkix"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const testDir = "/tmp/test_cert"

func TestMain(m *testing.M) {
	os.RemoveAll(testDir)
	code := m.Run()
	os.RemoveAll(testDir)
	os.Exit(code)
}

func TestNewCertDefault(t *testing.T) {
	cert := NewCert(nil)
	assert.Equal(t, "ca", cert.Name, "Default certificate name")
	default_dir, _ := filepath.Abs("./")
	assert.Equal(t, default_dir, cert.Dir, "Default certificate file dir")
	assert.Equal(t, default_dir+"/ca.crt", cert.CertFile, "Default certificate file name")
	assert.Equal(t, default_dir+"/ca.key", cert.KeyFile, "Default private key file name")
	assert.Nil(t, cert.Cert, "Empty certificate")
	assert.Nil(t, cert.PrivateKey, "Empty private key")
}

func TestNewCert(t *testing.T) {
	cert := NewCert(&CertLocation{
		Name: " -Test - CA ",
		Dir:  "/tmp/smth/../test_cert",
	})
	assert.Equal(t, "-Test - CA", cert.Name, "Normalized certificate name")
	assert.Equal(t, testDir, cert.Dir, "Normalized certificate file dir")
	assert.Equal(t, testDir+"/test-ca.crt", cert.CertFile, "Normalized certificate file name")
	assert.Equal(t, testDir+"/test-ca.key", cert.KeyFile, "Normalized private key file name")
	assert.Nil(t, cert.Cert, "Empty certificate")
	assert.Nil(t, cert.PrivateKey, "Empty private key")
}

func TestCreateNewCert(t *testing.T) {
	cert := NewCert(&CertLocation{
		Name: "test $ CA",
		Dir:  "/tmp/./test_cert",
	})

	// Try to load cert from testDir
	err := cert.Load()
	assert.Error(t, err, "Certificate not found")

	// Generate new CA certificate
	subject := pkix.Name{
		Country:            []string{"Test Country"},
		Organization:       []string{"Test Organization"},
		OrganizationalUnit: []string{"Test Unit"},
		Locality:           []string{"Test Locality"},
		Province:           []string{"Test Province"},
		StreetAddress:      []string{"Test Address"},
		PostalCode:         []string{"Test Postal Code"},
		SerialNumber:       "",
		CommonName:         "Test",
		Names:              []pkix.AttributeTypeAndValue{},
		ExtraNames:         []pkix.AttributeTypeAndValue{},
	}

	newCAcert := PrepareCA(subject, time.Now(), time.Now().AddDate(0, 0, 1))

	// Generate new CA cert and private key
	err = cert.AddCertAndKey(newCAcert, 4096)
	assert.NoError(t, err, "No error creating new CA certificate")

	// Generate one more time (idempotent operation)
	err = cert.AddCertAndKey(newCAcert, 4096)
	assert.NoError(t, err, "No error creating new CA certificate")

	// Save new CA cert
	err = cert.Save(nil)
	assert.NoError(t, err, "No error while saving new CA certificate")
	assert.True(t, cert.ExistsBoth(), "Both file should exist")

	err = cert.AddCertAndKey(newCAcert, 4096)
	assert.Error(t, err, "Inposible to recreate certificate after saving")
}

func TestSignNewCert(t *testing.T) {
	cert := NewCert(&CertLocation{
		Name: "Test CA",
		Dir:  "/tmp/./test_cert",
	})

	// Try to load cert from testDir
	err := cert.Load()
	assert.NoError(t, err, "Certificate should be found")

	assert.NotEmpty(t, cert.Cert, "Certificate should be loaded")
	assert.NotEmpty(t, cert.PrivateKey, "Key pair should be loaded")

	// Initiate new certificate wrapper
	clientCert := NewCert(&CertLocation{
		Name: "Client",
		Dir:  "/tmp/test_cert",
	})

	// Try to load cert from testDir
	err = clientCert.Load()
	assert.Error(t, err, "Certificate not found")

	// Generate new CA certificate
	subject := pkix.Name{
		Country:            []string{"Test Country"},
		Organization:       []string{"Test Organization"},
		OrganizationalUnit: []string{"Test Unit"},
		Locality:           []string{"Test Locality"},
		Province:           []string{"Test Province"},
		StreetAddress:      []string{"Test Address"},
		PostalCode:         []string{"Test Postal Code"},
		SerialNumber:       "",
		CommonName:         "Test Client",
		Names:              []pkix.AttributeTypeAndValue{},
		ExtraNames:         []pkix.AttributeTypeAndValue{},
	}

	err = clientCert.AddCertAndKey(
		PrepareCert(subject, []string{}, time.Now(), time.Now().AddDate(0, 0, 1)),
		2048,
	)
	assert.NoError(t, err, "No error creating new certificate")

	err = clientCert.Save(cert)
	assert.NoError(t, err, "No error saving certificate")
}
