package proxy

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"hash"
	"io/ioutil"
	"net/http"
	"strings"
)

// Constants.
var signedHeaders = []string{
	"Content-Length",
	"Content-Md5",
	"Content-Type",
	"Date",
	"Authorization",
	"X-Forwarded-User",
	"X-Forwarded-Email",
	"X-Forwarded-Groups",
	"Cookie",
}
var signatureHeader = "Octoboi-Signature"

// RequestSigner type.
type RequestSigner struct {
	hasher       hash.Hash
	signingKey   crypto.Signer
	publicKeyStr string
}

// NewRequestSigner constructs an object capable of signing requests with a public key.
func NewRequestSigner(signingKeyPemStr string) (*RequestSigner, error) {
	var privateKey crypto.Signer
	var publicKey string

	// Build private key.
	if block, _ := pem.Decode([]byte(signingKeyPemStr)); block == nil {
		return nil, fmt.Errorf("could not read PEM block from signing key")
	} else if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		return nil, fmt.Errorf("could not read key from signing key bytes: %s", err)
	} else {
		privateKey = key.(crypto.Signer)
	}

	// Derive public key.
	rsaPublicKey, ok := privateKey.Public().(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("only RSA public keys are currently supported")
	}
	publicKey = string(pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(rsaPublicKey),
		}))

	return &RequestSigner{
		hasher:       sha256.New(),
		signingKey:   privateKey,
		publicKeyStr: publicKey,
	}, nil
}

// Sign adds a header to the request, with a public-key encrypted signature of a subset of the
// request headers, together with the request body.
func (signer RequestSigner) Sign(req *http.Request) error {
	var documentBuffer bytes.Buffer

	// Write all signed request headers to the document buffer.
	for _, hdr := range signedHeaders {
		_, _ = documentBuffer.WriteString(strings.Join(req.Header[hdr], ",") + "\n")
	}
	// Write the URL to the document buffer. Exclude scheme, host, port, etc.
	_, _ = documentBuffer.WriteString(req.URL.Path)
	if len(req.URL.RawQuery) > 0 {
		_, _ = documentBuffer.WriteString("?" + req.URL.RawQuery)
	}
	if len(req.URL.Fragment) > 0 {
		_, _ = documentBuffer.WriteString("#" + req.URL.Fragment)
	}
	_, _ = documentBuffer.WriteString("\n")

	// Write the request body to the document buffer.
	if req.Body != nil {
		body, _ := ioutil.ReadAll(req.Body)
		req.Body = ioutil.NopCloser(bytes.NewBuffer(body))
		_, _ = documentBuffer.Write(body)
	}

	// Generate hash of the document buffer.
	var documentHash []byte
	signer.hasher.Reset()
	_, _ = signer.hasher.Write(documentBuffer.Bytes())
	documentHash = signer.hasher.Sum(documentHash)

	// Sign the documentHash with the signing key.
	signatureBytes, err := signer.signingKey.Sign(rand.Reader, documentHash, nil /* opts */)
	if err != nil {
		return fmt.Errorf("failed signing document hash with signing key: %s", err)
	}
	signature := base64.URLEncoding.EncodeToString(signatureBytes)

	// Set the signature-header on the rest. Return `nil` to indicate no error.
	req.Header.Set(signatureHeader, signature)
	return nil
}

// PublicKey returns a string PEM-encoded representation of the public key associated with the
// private key used to sign requests.
func (signer RequestSigner) PublicKey() string {
	return signer.publicKeyStr
}
