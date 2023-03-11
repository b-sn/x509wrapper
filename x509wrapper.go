package x509wrapper

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const defaultCAname = "ca"

type X509CertWrapper struct {
	Name       string
	Dir        string
	Cert       *x509.Certificate
	CertFile   string
	PrivateKey *rsa.PrivateKey
	KeyFile    string
}

func NewCert(name string, dir string) *X509CertWrapper {
	cert := &X509CertWrapper{
		Name: defaultCAname,
		Dir:  "./",
	}

	defer cert.normalize()

	if name != "" {
		cert.Name = name
	}
	if dir != "" {
		cert.Dir = dir
	}

	return cert
}

// Add a new certificate to X509CertWrapper srtuct
// and generate RSA private key with keyBits length
func (c *X509CertWrapper) AddCertAndKey(cert *x509.Certificate, keyBits int) error {

	if c.ExistsAny() {
		return fmt.Errorf(
			"certificate '%s' already exists in directory '%s', consider to load it instead",
			c.Name,
			c.Dir,
		)
	}

	privateKey, err := generateRSAKey(keyBits)
	if err != nil {
		return err
	}

	c.PrivateKey = privateKey
	c.Cert = cert

	return nil
}

// Check if either the certificate or the private key files exist
func (c *X509CertWrapper) ExistsAny() bool {
	return fileExists(c.CertFile) || fileExists(c.KeyFile)
}

// Check if both the certificate and the private key files exist
func (c *X509CertWrapper) ExistsBoth() bool {
	return fileExists(c.CertFile) && fileExists(c.KeyFile)
}

// Load certificate and private key from files
func (c *X509CertWrapper) Load() error {
	certData, err := readDataFromFile(c.CertFile)
	if err != nil {
		return err
	}

	c.Cert, err = x509.ParseCertificate(certData)
	if err != nil {
		return fmt.Errorf(
			"failed to parse certificate data from file [%s]: %w",
			c.CertFile,
			err,
		)
	}

	privateKeyData, err := readDataFromFile(c.KeyFile)
	if err != nil {
		return err
	}

	c.PrivateKey, err = x509.ParsePKCS1PrivateKey(privateKeyData)
	if err != nil {
		return fmt.Errorf(
			"failed to parse private key from file [%s]: %w",
			c.KeyFile,
			err,
		)
	}

	return nil
}

// Save certificate and private key to files
// Optionally, another certificate can be send as a parameter as a signer
func (c *X509CertWrapper) Save(signBy *X509CertWrapper) error {

	if signBy == nil {
		signBy = c
	} else {
		if signBy.Cert == nil {
			return fmt.Errorf("generate certificate before saving")
		}
		if signBy.PrivateKey == nil {
			return fmt.Errorf("generate private key before saving")
		}
		if !signBy.ExistsBoth() {
			return fmt.Errorf("need to save cert files before signing")
		}
	}

	if c.Cert == nil {
		return fmt.Errorf("need to generate certificate before saving")
	}
	if c.PrivateKey == nil {
		return fmt.Errorf("need to generate private key before saving")
	}

	if c.ExistsAny() {
		return fmt.Errorf(
			"certificate with name %s already exists in directory %s",
			c.Name,
			c.Dir,
		)
	}

	caBytes, err := x509.CreateCertificate(
		rand.Reader,
		c.Cert,
		signBy.Cert,
		&c.PrivateKey.PublicKey,
		signBy.PrivateKey,
	)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %w", err)
	}

	// Save certificate
	if err := writeDataToFile(c.CertFile, caBytes, "CERTIFICATE"); err != nil {
		return err
	}

	// Save private key
	if err := writeDataToFile(
		c.KeyFile,
		x509.MarshalPKCS1PrivateKey(c.PrivateKey),
		"RSA PRIVATE KEY",
	); err != nil {
		os.Remove(c.CertFile)
		return err
	}

	return nil
}

// Fill X509CertWrapper with correct data after creation
func (c *X509CertWrapper) normalize() {

	absDir, err := filepath.Abs(c.Dir)
	if err != nil {
		panic(err)
	}

	fileName := normalizeName(c.Name)

	c.Dir = absDir
	c.Name = strings.Trim(c.Name, " ")
	c.CertFile = filepath.Join(c.Dir, fmt.Sprintf("%s.crt", fileName))
	c.KeyFile = filepath.Join(c.Dir, fmt.Sprintf("%s.key", fileName))
}

// Return CA certificate
func PrepareCA(subj pkix.Name, notBefore time.Time, notAfter time.Time) *x509.Certificate {

	return &x509.Certificate{
		SerialNumber:          createSerialNumber(),
		Subject:               subj,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
}

// Return X509 certificate for server or clients
// This certificate must be signed by CA certificate
func PrepareCert(subj pkix.Name, dns []string, notBefore time.Time, notAfter time.Time) *x509.Certificate {

	return &x509.Certificate{
		SerialNumber: createSerialNumber(),
		Subject:      subj,
		DNSNames:     dns,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
}

// Return cerial number for certificate based on current timestamp
func createSerialNumber() *big.Int {
	return big.NewInt(time.Now().UnixMicro())
}

// Check if file exists by its path
func fileExists(filePath string) bool {
	_, err := os.Stat(filePath)
	return err == nil || !os.IsNotExist(err)
}

// Generate RSA key pair of the given bit size
func generateRSAKey(bitSize int) (*rsa.PrivateKey, error) {

	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA private key: %w", err)
	}

	return privateKey, nil
}

// Prepare certificate file name from certificate name
func normalizeName(name string) string {

	re := regexp.MustCompile(`\W+`)
	res := re.ReplaceAll([]byte(name), []byte("-"))

	re = regexp.MustCompile(`\-{2,}`)
	res = re.ReplaceAll(res, []byte("-"))

	return strings.ToLower(strings.Trim(string(res), "-"))
}

// Read data from key file and decode
func readDataFromFile(filePath string) ([]byte, error) {

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file : %w", err)
	}

	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM from file [%s]: %w", filePath, err)
	}

	return pemBlock.Bytes, nil
}

// Write key data to file
func writeDataToFile(absFilePath string, data []byte, pemType string) error {

	if _, err := os.Stat(absFilePath); os.IsExist(err) {
		return fmt.Errorf("file with name [%s] alredy exists", absFilePath)
	}

	pemData := new(bytes.Buffer)
	err := pem.Encode(pemData, &pem.Block{Type: pemType, Bytes: data})
	if err != nil {
		return fmt.Errorf("failed to encode PEM: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(absFilePath), 0700); err != nil {
		return err
	}

	if err := os.WriteFile(absFilePath, pemData.Bytes(), 0600); err != nil {
		return fmt.Errorf("failed to write certificate file: %w", err)
	}

	return nil
}
