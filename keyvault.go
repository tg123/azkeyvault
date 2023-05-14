package azkeyvault

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"

	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
)

var (
	// ErrUnsupportedHash is returned by Signer.Sign() when the provided hash
	// algorithm isn't supported.
	ErrUnsupportedHash = fmt.Errorf("unsupported hash algorithm")
)

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
	GetKey(ctx context.Context, name string, version string, options *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error)
}

type azurekeyVaultApi struct {
	keyClient *azkeys.Client
}

func (a *azurekeyVaultApi) Sign(ctx context.Context, name string, version string, parameters azkeys.SignParameters, options *azkeys.SignOptions) (azkeys.SignResponse, error) {
	return a.keyClient.Sign(ctx, name, version, parameters, options)
}

func (a *azurekeyVaultApi) Decrypt(ctx context.Context, name string, version string, parameters azkeys.KeyOperationsParameters, options *azkeys.DecryptOptions) (azkeys.DecryptResponse, error) {
	return a.keyClient.Decrypt(ctx, name, version, parameters, options)
}

func (a *azurekeyVaultApi) GetKey(ctx context.Context, name string, version string, options *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error) {
	return a.keyClient.GetKey(ctx, name, version, options)
}

func toPublicKey(k azkeys.GetKeyResponse) (crypto.PublicKey, error) {

	switch *k.Key.Kty {
	case azkeys.JSONWebKeyTypeRSA, azkeys.JSONWebKeyTypeRSAHSM:
		N := new(big.Int).SetBytes(k.Key.N)
		E := new(big.Int).SetBytes(k.Key.E)

		return &rsa.PublicKey{
			N: N,
			E: int(E.Int64()),
		}, nil

	case azkeys.JSONWebKeyTypeEC, azkeys.JSONWebKeyTypeECHSM:
		X := new(big.Int).SetBytes(k.Key.X)
		Y := new(big.Int).SetBytes(k.Key.Y)

		var crv elliptic.Curve
		switch *k.Key.Crv {
		case azkeys.JSONWebKeyCurveNameP256, azkeys.JSONWebKeyCurveNameP256K:
			crv = elliptic.P256()
		case azkeys.JSONWebKeyCurveNameP384:
			crv = elliptic.P384()
		case azkeys.JSONWebKeyCurveNameP521:
			crv = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported curve: %v", *k.Key.Crv)
		}

		return &ecdsa.PublicKey{
			Curve: crv,
			X:     X,
			Y:     Y,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %s", *k.Key.Kty)
	}
}

var _ crypto.Signer = &keyVaultInst{}
var _ crypto.Decrypter = &keyVaultInst{}

type keyVaultInst struct {
	client     keyVaultApi
	keyName    string
	keyVersion string

	publickey crypto.PublicKey
}

func NewSigner(
	keyClient *azkeys.Client,
	keyName string,
	keyVersion string,
) (crypto.Signer, error) {
	return newInst(keyClient, keyName, keyVersion)
}

func NewDecrypter(
	keyClient *azkeys.Client,
	keyName string,
	keyVersion string,
) (crypto.Decrypter, error) {
	return newInst(keyClient, keyName, keyVersion)
}

func newInst(
	keyClient keyVaultApi,
	keyName string,
	keyVersion string,
) (*keyVaultInst, error) {

	if keyClient == nil {
		return nil, fmt.Errorf("keyClient is nil")
	}

	c := keyVaultInst{
		client:     keyClient,
		keyName:    keyName,
		keyVersion: keyVersion,
	}

	k, err := c.client.GetKey(context.Background(), keyName, keyVersion, nil)
	if err != nil {
		return nil, err
	}

	c.publickey, err = toPublicKey(k)
	if err != nil {
		return nil, err
	}

	return &c, nil
}

func (v *keyVaultInst) Public() crypto.PublicKey {
	return v.publickey
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
