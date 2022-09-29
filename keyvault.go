package azkeyvault

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
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

// for testing
type keyVaultApi interface {
	Sign(ctx context.Context, name string, version string, parameters azkeys.SignParameters, options *azkeys.SignOptions) (azkeys.SignResponse, error)
	Decrypt(ctx context.Context, name string, version string, parameters azkeys.KeyOperationsParameters, options *azkeys.DecryptOptions) (azkeys.DecryptResponse, error)
	GetCertificate(ctx context.Context, certificateName string, certificateVersion string, options *azcertificates.GetCertificateOptions) (azcertificates.GetCertificateResponse, error)
}

type azurekeyVaultApi struct {
	keyClient  *azkeys.Client
	certClient *azcertificates.Client
}

func (a *azurekeyVaultApi) Sign(ctx context.Context, name string, version string, parameters azkeys.SignParameters, options *azkeys.SignOptions) (azkeys.SignResponse, error) {
	return a.keyClient.Sign(ctx, name, version, parameters, options)
}

func (a *azurekeyVaultApi) Decrypt(ctx context.Context, name string, version string, parameters azkeys.KeyOperationsParameters, options *azkeys.DecryptOptions) (azkeys.DecryptResponse, error) {
	return a.keyClient.Decrypt(ctx, name, version, parameters, options)
}

func (a *azurekeyVaultApi) GetCertificate(ctx context.Context, certificateName string, certificateVersion string, options *azcertificates.GetCertificateOptions) (azcertificates.GetCertificateResponse, error) {
	return a.certClient.GetCertificate(ctx, certificateName, certificateVersion, options)
}

type keyVaultInst struct {
	client     keyVaultApi
	keyName    string
	keyVersion string

	cert *x509.Certificate
	lock sync.Mutex
}

func NewSigner(
	keyClient *azkeys.Client,
	certClient *azcertificates.Client,
	keyName string,
	keyVersion string,
) (Signer, error) {
	return newInst(keyClient, certClient, keyName, keyVersion)
}

func NewDecrypter(
	keyVaultClient *azkeys.Client,
	certClient *azcertificates.Client,
	keyName string,
	keyVersion string,
) (Decrypter, error) {
	return newInst(keyVaultClient, certClient, keyName, keyVersion)
}

func newInst(
	keyClient *azkeys.Client,
	certClient *azcertificates.Client,
	keyName string,
	keyVersion string,
) (*keyVaultInst, error) {

	c := keyVaultInst{
		client:     &azurekeyVaultApi{keyClient: keyClient, certClient: certClient},
		keyName:    keyName,
		keyVersion: keyVersion,
	}

	return &c, nil
}

func (v *keyVaultInst) Certificate() (*x509.Certificate, error) {
	if v.cert != nil {
		return v.cert, nil
	}

	v.lock.Lock()
	defer v.lock.Unlock()

	r, err := v.client.GetCertificate(context.Background(), v.keyName, v.keyVersion, nil)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(r.CER)
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
	Algorithm azkeys.JSONWebKeySignatureAlgorithm
	Context   context.Context
}

func (o *SignerOpts) HashFunc() crypto.Hash {
	switch o.Algorithm {
	case azkeys.JSONWebKeySignatureAlgorithmES256, azkeys.JSONWebKeySignatureAlgorithmES256K, azkeys.JSONWebKeySignatureAlgorithmPS256, azkeys.JSONWebKeySignatureAlgorithmRS256:
		return crypto.SHA256
	case azkeys.JSONWebKeySignatureAlgorithmES384, azkeys.JSONWebKeySignatureAlgorithmPS384, azkeys.JSONWebKeySignatureAlgorithmRS384:
		return crypto.SHA384
	case azkeys.JSONWebKeySignatureAlgorithmES512, azkeys.JSONWebKeySignatureAlgorithmPS512, azkeys.JSONWebKeySignatureAlgorithmRS512:
		return crypto.SHA512
	}
	return 0
}

func (v *keyVaultInst) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	hash := opts.HashFunc()
	if len(digest) != hash.Size() {
		return nil, fmt.Errorf("bad digest for hash")
	}

	var algo azkeys.JSONWebKeySignatureAlgorithm
	var ctx context.Context

	switch opt := opts.(type) {
	case *rsa.PSSOptions:
		switch hash {
		case crypto.SHA256:
			algo = azkeys.JSONWebKeySignatureAlgorithmPS256
		case crypto.SHA384:
			algo = azkeys.JSONWebKeySignatureAlgorithmPS384
		case crypto.SHA512:
			algo = azkeys.JSONWebKeySignatureAlgorithmPS512
		default:
			return nil, ErrUnsupportedHash
		}
	case *SignerOpts:
		algo = opt.Algorithm
		ctx = opt.Context
	default:
		switch hash {
		case crypto.SHA1:
			algo = azkeys.JSONWebKeySignatureAlgorithmRSNULL
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
			algo = azkeys.JSONWebKeySignatureAlgorithmRS256
		case crypto.SHA384:
			algo = azkeys.JSONWebKeySignatureAlgorithmRS384
		case crypto.SHA512:
			algo = azkeys.JSONWebKeySignatureAlgorithmRS512
		default:
			return nil, ErrUnsupportedHash
		}
	}

	if ctx == nil {
		ctx = context.Background()
	}

	r, err := v.client.Sign(ctx, v.keyName, v.keyVersion, azkeys.SignParameters{
		Algorithm: &algo,
		Value:     digest,
	}, nil)
	if err != nil {
		return nil, err
	}

	return r.Result, nil
}

type DecrypterOpts struct {
	Algorithm azkeys.JSONWebKeyEncryptionAlgorithm
	Context   context.Context
}

func (v *keyVaultInst) Decrypt(_ io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {

	algo := azkeys.JSONWebKeyEncryptionAlgorithmRSA15

	var ctx context.Context

	if opt, ok := opts.(*DecrypterOpts); ok {
		algo = opt.Algorithm
		ctx = opt.Context
	}

	if ctx == nil {
		ctx = context.Background()
	}

	r, err := v.client.Decrypt(ctx, v.keyName, v.keyVersion, azkeys.KeyOperationsParameters{
		Algorithm: &algo,
		Value:     msg,
	}, nil)
	if err != nil {
		return nil, err
	}

	return r.Result, nil
}
