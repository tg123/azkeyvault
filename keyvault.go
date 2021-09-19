package azkeyvault

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"io"
	"sync"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault"
	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault/keyvaultapi"
)

var (
	// ErrUnsupportedHash is returned by Signer.Sign() when the provided hash
	// algorithm isn't supported.
	ErrUnsupportedHash = fmt.Errorf("unsupported hash algorithm")
)

type Signer interface {
	crypto.Signer

	// Certificate return x509 certificate of Signer
	Certificate() (*x509.Certificate, error)
}

type Decrypter interface {
	crypto.Decrypter

	// Certificate return x509 certificate of Decrypter
	Certificate() (*x509.Certificate, error)
}

type digestAlgorithmIdentifier struct {
	AlgoId asn1.ObjectIdentifier
	Param  interface{}
}

type digestInfo struct {
	Algorithm digestAlgorithmIdentifier
	Digest    []byte
}

var sha1Oid = asn1.ObjectIdentifier([]int{1, 3, 14, 3, 2, 26}) // https://datatracker.ietf.org/doc/html/rfc3279#section-2.2.1

type keyVaultInst struct {
	keyVaultClient keyvaultapi.BaseClientAPI
	vaultBaseURL   string
	keyName        string
	keyVersion     string

	cert *x509.Certificate
	lock sync.Mutex
}

func NewSigner(
	keyVaultClient keyvaultapi.BaseClientAPI,
	vaultBaseURL string,
	keyName string,
	keyVersion string,
) (Signer, error) {
	return newInst(keyVaultClient, vaultBaseURL, keyName, keyVersion)
}

func NewDecrypter(
	keyVaultClient keyvaultapi.BaseClientAPI,
	vaultBaseURL string,
	keyName string,
	keyVersion string,
) (Decrypter, error) {
	return newInst(keyVaultClient, vaultBaseURL, keyName, keyVersion)
}

func newInst(
	keyVaultClient keyvaultapi.BaseClientAPI,
	vaultBaseURL string,
	keyName string,
	keyVersion string,
) (*keyVaultInst, error) {

	c := keyVaultInst{
		keyVaultClient: keyVaultClient,
		vaultBaseURL:   vaultBaseURL,
		keyName:        keyName,
		keyVersion:     keyVersion,
	}

	return &c, nil
}

func (v *keyVaultInst) Certificate() (*x509.Certificate, error) {
	if v.cert != nil {
		return v.cert, nil
	}

	v.lock.Lock()
	defer v.lock.Unlock()

	r, err := v.keyVaultClient.GetCertificate(context.Background(), v.vaultBaseURL, v.keyName, v.keyVersion)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(*r.Cer)
	if err != nil {
		return nil, err
	}

	v.cert = cert

	return cert, nil
}

func (v *keyVaultInst) Public() crypto.PublicKey {
	if cert, err := v.Certificate(); err == nil {
		return cert.PublicKey
	}

	return nil
}

type SignerOpts struct {
	Algorithm keyvault.JSONWebKeySignatureAlgorithm
	Context   context.Context
}

func (o *SignerOpts) HashFunc() crypto.Hash {
	switch o.Algorithm {
	case keyvault.ES256, keyvault.ES256K, keyvault.PS256, keyvault.RS256:
		return crypto.SHA256
	case keyvault.ES384, keyvault.PS384, keyvault.RS384:
		return crypto.SHA384
	case keyvault.ES512, keyvault.PS512, keyvault.RS512:
		return crypto.SHA512
	}
	return 0
}

func (v *keyVaultInst) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	hash := opts.HashFunc()
	if len(digest) != hash.Size() {
		return nil, fmt.Errorf("bad digest for hash")
	}

	var algo keyvault.JSONWebKeySignatureAlgorithm
	var ctx context.Context

	switch opt := opts.(type) {
	case *rsa.PSSOptions:
		switch hash {
		case crypto.SHA256:
			algo = keyvault.PS256
		case crypto.SHA384:
			algo = keyvault.PS384
		case crypto.SHA512:
			algo = keyvault.PS512
		default:
			return nil, ErrUnsupportedHash
		}
	case *SignerOpts:
		algo = opt.Algorithm
		ctx = opt.Context
	default:
		switch hash {
		case crypto.SHA1:
			algo = keyvault.RSNULL
			digest, err = asn1.Marshal(digestInfo{
				Algorithm: digestAlgorithmIdentifier{
					AlgoId: sha1Oid,
					Param:  asn1.NullRawValue,
				},
				Digest: digest,
			})
			if err != nil {
				return nil, err
			}

		case crypto.SHA256:
			algo = keyvault.RS256
		case crypto.SHA384:
			algo = keyvault.RS384
		case crypto.SHA512:
			algo = keyvault.RS512
		default:
			return nil, ErrUnsupportedHash
		}
	}

	if ctx == nil {
		ctx = context.Background()
	}

	r, err := v.keyVaultClient.Sign(ctx, v.vaultBaseURL, v.keyName, v.keyVersion, keyvault.KeySignParameters{
		Algorithm: algo,
		Value:     base64encode(digest),
	})
	if err != nil {
		return nil, err
	}

	return base64decode(r.Result)
}

type DecrypterOpts struct {
	Algorithm keyvault.JSONWebKeyEncryptionAlgorithm
	Context   context.Context
}

func (v *keyVaultInst) Decrypt(_ io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {

	algo := keyvault.RSA15

	var ctx context.Context

	if opt, ok := opts.(*DecrypterOpts); ok {
		algo = opt.Algorithm
		ctx = opt.Context
	}

	if ctx == nil {
		ctx = context.Background()
	}

	r, err := v.keyVaultClient.Decrypt(ctx, v.vaultBaseURL, v.keyName, v.keyVersion, keyvault.KeyOperationsParameters{
		Algorithm: algo,
		Value:     base64encode(msg),
	})
	if err != nil {
		return nil, err
	}

	return base64decode(r.Result)
}

func base64encode(b []byte) *string {
	s := base64.RawURLEncoding.EncodeToString(b)
	return &s
}

func base64decode(s *string) ([]byte, error) {
	if s == nil {
		return nil, fmt.Errorf("api result empty")
	}

	return base64.RawURLEncoding.DecodeString(*s)
}
