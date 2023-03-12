package azkeyvault

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
)

func TestPublic(t *testing.T) {
	m := newMockApi()

	var signer Signer = &keyVaultInst{
		client:     m,
		keyName:    "keyname",
		keyVersion: "keyvers",
	}

	cert, err := x509.ParseCertificate(m.cert)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("eq", func(t *testing.T) {
		if !cert.PublicKey.(*rsa.PublicKey).Equal(signer.Public()) {
			t.Error("wrong public key returned")
		}
	})

	t.Run("param", func(t *testing.T) {
		p := m.popParam()

		if p[1] != "keyname" {
			t.Error("wrong param 1")
		}

		if p[2] != "keyvers" {
			t.Error("wrong param 2")
		}
	})

	t.Run("cached", func(t *testing.T) {
		m.newKey()
		c, err := signer.Certificate()
		if err != nil {
			t.Error(err)
		}

		if !c.Equal(cert) {
			t.Error("cert changed")
		}

		if len(m.calledParams) != 0 {
			t.Error("api called twice")
		}
	})
}

func TestSign(t *testing.T) {
	m := newMockApi()

	var signer Signer = &keyVaultInst{
		client:     m,
		keyName:    "keyname",
		keyVersion: "keyvers",
	}

	t.Run("sig pkcs15 256", func(t *testing.T) {

		msg := []byte("sig abc")
		hashed := sha256.Sum256(msg)

		sig, err := signer.Sign(rand.Reader, hashed[:], &SignerOpts{
			Algorithm: azkeys.JSONWebKeySignatureAlgorithmPS256,
		})

		if err != nil {
			t.Error(err)
		}

		if err := rsa.VerifyPKCS1v15(&m.privateKey.PublicKey, crypto.SHA256, hashed[:], sig); err != nil {
			t.Error(err)
		}
	})

	t.Run("param", func(t *testing.T) {
		p := m.popParam()

		if p[1] != "keyname" {
			t.Error("wrong param 1")
		}

		if p[2] != "keyvers" {
			t.Error("wrong param 2")
		}
	})

	for _, h := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		t.Run("sig pss auto", func(t *testing.T) {
			hashed := make([]byte, h.Size())
			if _, err := signer.Sign(rand.Reader, hashed, &rsa.PSSOptions{
				Hash: h,
			}); err != nil {
				t.Error(err)
			}

			p := m.popParam()
			param := p[3].(azkeys.SignParameters)

			opt := &SignerOpts{
				Algorithm: *param.Algorithm,
			}

			if opt.HashFunc() != h {
				t.Error("wrong pss hash size")
			}

			if !strings.HasPrefix(string(opt.Algorithm), "PS") {
				t.Error("algo not PSS")
			}
		})
	}

	for _, h := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		t.Run("sig pkcs auto", func(t *testing.T) {
			hashed := make([]byte, h.Size())
			if _, err := signer.Sign(rand.Reader, hashed, h); err != nil {
				t.Error(err)
			}

			p := m.popParam()
			param := p[3].(azkeys.SignParameters)

			opt := &SignerOpts{
				Algorithm: *param.Algorithm,
			}

			if opt.HashFunc() != h {
				t.Error("wrong pkcs hash size")
			}

			if !strings.HasPrefix(string(opt.Algorithm), "RS") {
				t.Error("algo not PKCS")
			}
		})
	}

}

func TestDecrypt(t *testing.T) {
	m := newMockApi()

	var decrypter Decrypter = &keyVaultInst{
		client:     m,
		keyName:    "keyname",
		keyVersion: "keyvers",
	}

	t.Run("dec", func(t *testing.T) {
		enc, err := rsa.EncryptPKCS1v15(rand.Reader, &m.privateKey.PublicKey, []byte("abcdefg"))
		if err != nil {
			t.Fatal(err)
		}

		dec, err := decrypter.Decrypt(rand.Reader, enc, nil)
		if err != nil {
			t.Fatal(err)
		}

		if string(dec) != "abcdefg" {
			t.Error("wrong decrypt value")
		}

	})

	t.Run("param", func(t *testing.T) {
		p := m.popParam()

		if p[1] != "keyname" {
			t.Error("wrong param 1")
		}

		if p[2] != "keyvers" {
			t.Error("wrong param 2")
		}
	})
}

type mockApi struct {
	privateKey   *rsa.PrivateKey
	cert         []byte
	calledParams [][]interface{}
}

func newMockApi() *mockApi {
	m := mockApi{}
	m.newKey()
	return &m
}

func (m *mockApi) newKey() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	m.privateKey = privateKey

	template := x509.Certificate{
		SerialNumber: big.NewInt(0),
	}

	cert, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		panic(err)
	}

	m.cert = cert
}

func (m *mockApi) popParam() (result []interface{}) {
	l := len(m.calledParams)
	result = m.calledParams[l-1]
	m.calledParams = m.calledParams[:l-1]
	return
}

func (m *mockApi) Sign(ctx context.Context, name string, version string, parameters azkeys.SignParameters, options *azkeys.SignOptions) (result azkeys.SignResponse, err error) {
	if ctx == nil {
		panic("panic context")
	}

	m.calledParams = append(m.calledParams, []interface{}{ctx, name, version, parameters, options})

	digest := parameters.Value

	var sig []byte
	sig, err = m.privateKey.Sign(rand.Reader, digest, &SignerOpts{
		Algorithm: *parameters.Algorithm,
	})
	if err != nil {
		return
	}

	result.Result = sig
	return
}

func (m *mockApi) Decrypt(ctx context.Context, name string, version string, parameters azkeys.KeyOperationsParameters, options *azkeys.DecryptOptions) (result azkeys.DecryptResponse, err error) {
	if ctx == nil {
		panic("panic context")
	}

	m.calledParams = append(m.calledParams, []interface{}{ctx, name, version, parameters, options})

	if *parameters.Algorithm != azkeys.JSONWebKeyEncryptionAlgorithmRSA15 {
		err = fmt.Errorf("not support")
		return
	}

	cipher := parameters.Value

	var plain []byte
	plain, err = m.privateKey.Decrypt(rand.Reader, cipher, nil)
	if err != nil {
		return
	}

	result.Result = plain
	return
}

func (m *mockApi) GetCertificate(ctx context.Context, certificateName string, certificateVersion string, options *azcertificates.GetCertificateOptions) (result azcertificates.GetCertificateResponse, err error) {
	m.calledParams = append(m.calledParams, []interface{}{ctx, certificateName, certificateVersion, options})
	result.CER = m.cert
	return
}
