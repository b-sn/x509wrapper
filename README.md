This module is a wrapper for the crypto/x509 module. It helps to create and sign all certificates required for mTLS connections.

Possible usage for creating new CA certificate:

```go
import (
	"crypto/x509/pkix"
	"time"

	"github.com/b-sn/x509wrapper"
)

CACert := x509wrapper.NewCert("CA", "./certs")

// Create a new CA cert and a private key
if err := CACert.AddCertAndKey(x509wrapper.PrepareCA(
	pkix.Name{
		…
	},
	time.Now(),
	time.Now().AddDate(1, 0, 0)), 4096,
); err != nil {
	Fatal("Problem with new CA certificate: %v", err)
}

// Save CA certificate
if err := CACert.Save(nil); err != nil {
	Fatal("Problem with saving CA certificate: %v", err)
}
```



To load existing certificate:

```go
Cert := x509wrapper.NewCert("Cert name", "./certs")
if err := Cert.Load(); err != nil {
	Fatal("Problem with loading certificate: %v", err)
}
```



To create a new certificate and sign with CA:

```go
newCert := x509wrapper.NewCert("Server cert", "./certs")

// Create new certificate
if err := newCert.AddCertAndKey(x509wrapper.PrepareCert(
	pkix.Name{
		…
	},
	[]string{DNS},
	time.Now(),
	time.Now().AddDate(1, 0, 0)), 2048,
); err != nil {
	Fatal("Make new Certificate error: %v", err)
}

// Use CACert to sign new certificate before saving
if err := newCert.Save(CACert); err != nil {
	Fatal("Save new Certificate error: %v", err)
}
```
