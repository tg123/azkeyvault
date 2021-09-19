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

	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault"
	"github.com/Azure/go-autorest/autorest"
)

func TestPublic(t *testing.T) {
	m := newMockApi()

	signer, err := NewSigner(m, "vaulturl", "keyname", "keyvers")
	if err != nil {
		t.Fatal(err)
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

		if p[1] != "vaulturl" {
			t.Error("wrong param 1")
		}

		if p[2] != "keyname" {
			t.Error("wrong param 2")
		}

		if p[3] != "keyvers" {
			t.Error("wrong param 3")
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
	signer, err := NewSigner(m, "vaulturl", "keyname", "keyvers")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("sig pkcs15 256", func(t *testing.T) {

		msg := []byte("sig abc")
		hashed := sha256.Sum256(msg)

		sig, err := signer.Sign(rand.Reader, hashed[:], &SignerOpts{
			Algorithm: keyvault.PS256,
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

		if p[1] != "vaulturl" {
			t.Error("wrong param 1")
		}

		if p[2] != "keyname" {
			t.Error("wrong param 2")
		}

		if p[3] != "keyvers" {
			t.Error("wrong param 3")
		}
	})

	for _, h := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		t.Run("sig pss auto", func(t *testing.T) {
			hashed := make([]byte, h.Size())
			signer.Sign(rand.Reader, hashed, &rsa.PSSOptions{
				Hash: h,
			})

			p := m.popParam()
			param := p[4].(keyvault.KeySignParameters)

			opt := &SignerOpts{
				Algorithm: param.Algorithm,
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
			signer.Sign(rand.Reader, hashed, h)

			p := m.popParam()
			param := p[4].(keyvault.KeySignParameters)

			opt := &SignerOpts{
				Algorithm: param.Algorithm,
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

	decrypter, err := NewDecrypter(m, "vaulturl", "keyname", "keyvers")
	if err != nil {
		t.Fatal(err)
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

		if p[1] != "vaulturl" {
			t.Error("wrong param 1")
		}

		if p[2] != "keyname" {
			t.Error("wrong param 2")
		}

		if p[3] != "keyvers" {
			t.Error("wrong param 3")
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

func (m *mockApi) Sign(ctx context.Context, vaultBaseURL string, keyName string, keyVersion string, parameters keyvault.KeySignParameters) (result keyvault.KeyOperationResult, err error) {
	if ctx == nil {
		panic("panic context")
	}

	m.calledParams = append(m.calledParams, []interface{}{ctx, vaultBaseURL, keyName, keyVersion, parameters})

	var digest []byte
	digest, err = base64decode(parameters.Value)
	if err != nil {
		return
	}

	var sig []byte
	sig, err = m.privateKey.Sign(rand.Reader, digest, &SignerOpts{
		Algorithm: parameters.Algorithm,
	})
	if err != nil {
		return
	}

	result.Result = base64encode(sig)
	return
}

func (m *mockApi) Decrypt(ctx context.Context, vaultBaseURL string, keyName string, keyVersion string, parameters keyvault.KeyOperationsParameters) (result keyvault.KeyOperationResult, err error) {
	if ctx == nil {
		panic("panic context")
	}

	m.calledParams = append(m.calledParams, []interface{}{ctx, vaultBaseURL, keyName, keyVersion, parameters})

	if parameters.Algorithm != keyvault.RSA15 {
		err = fmt.Errorf("not support")
		return
	}

	var cipher []byte
	cipher, err = base64decode(parameters.Value)
	if err != nil {
		return
	}

	var plain []byte
	plain, err = m.privateKey.Decrypt(rand.Reader, cipher, nil)
	if err != nil {
		return
	}

	result.Result = base64encode(plain)
	return
}

func (m *mockApi) GetCertificate(ctx context.Context, vaultBaseURL string, certificateName string, certificateVersion string) (result keyvault.CertificateBundle, err error) {
	m.calledParams = append(m.calledParams, []interface{}{ctx, vaultBaseURL, certificateName, certificateVersion})
	result.Cer = &m.cert
	return
}

// #region unused keyvault api
func (m *mockApi) BackupCertificate(ctx context.Context, vaultBaseURL string, certificateName string) (result keyvault.BackupCertificateResult, err error) {
	panic("not implemented")
}

func (m *mockApi) BackupKey(ctx context.Context, vaultBaseURL string, keyName string) (result keyvault.BackupKeyResult, err error) {
	panic("not implemented")
}

func (m *mockApi) BackupSecret(ctx context.Context, vaultBaseURL string, secretName string) (result keyvault.BackupSecretResult, err error) {
	panic("not implemented")
}

func (m *mockApi) BackupStorageAccount(ctx context.Context, vaultBaseURL string, storageAccountName string) (result keyvault.BackupStorageResult, err error) {
	panic("not implemented")
}

func (m *mockApi) CreateCertificate(ctx context.Context, vaultBaseURL string, certificateName string, parameters keyvault.CertificateCreateParameters) (result keyvault.CertificateOperation, err error) {
	panic("not implemented")
}

func (m *mockApi) CreateKey(ctx context.Context, vaultBaseURL string, keyName string, parameters keyvault.KeyCreateParameters) (result keyvault.KeyBundle, err error) {
	panic("not implemented")
}

func (m *mockApi) Encrypt(ctx context.Context, vaultBaseURL string, keyName string, keyVersion string, parameters keyvault.KeyOperationsParameters) (result keyvault.KeyOperationResult, err error) {
	panic("not implemented")
}

func (m *mockApi) DeleteCertificate(ctx context.Context, vaultBaseURL string, certificateName string) (result keyvault.DeletedCertificateBundle, err error) {
	panic("not implemented")
}

func (m *mockApi) DeleteCertificateContacts(ctx context.Context, vaultBaseURL string) (result keyvault.Contacts, err error) {
	panic("not implemented")
}

func (m *mockApi) DeleteCertificateIssuer(ctx context.Context, vaultBaseURL string, issuerName string) (result keyvault.IssuerBundle, err error) {
	panic("not implemented")
}

func (m *mockApi) DeleteCertificateOperation(ctx context.Context, vaultBaseURL string, certificateName string) (result keyvault.CertificateOperation, err error) {
	panic("not implemented")
}

func (m *mockApi) DeleteKey(ctx context.Context, vaultBaseURL string, keyName string) (result keyvault.DeletedKeyBundle, err error) {
	panic("not implemented")
}

func (m *mockApi) DeleteSasDefinition(ctx context.Context, vaultBaseURL string, storageAccountName string, sasDefinitionName string) (result keyvault.DeletedSasDefinitionBundle, err error) {
	panic("not implemented")
}

func (m *mockApi) DeleteSecret(ctx context.Context, vaultBaseURL string, secretName string) (result keyvault.DeletedSecretBundle, err error) {
	panic("not implemented")
}

func (m *mockApi) DeleteStorageAccount(ctx context.Context, vaultBaseURL string, storageAccountName string) (result keyvault.DeletedStorageBundle, err error) {
	panic("not implemented")
}

func (m *mockApi) GetCertificateContacts(ctx context.Context, vaultBaseURL string) (result keyvault.Contacts, err error) {
	panic("not implemented")
}

func (m *mockApi) GetCertificateIssuer(ctx context.Context, vaultBaseURL string, issuerName string) (result keyvault.IssuerBundle, err error) {
	panic("not implemented")
}

func (m *mockApi) GetCertificateIssuers(ctx context.Context, vaultBaseURL string, maxresults *int32) (result keyvault.CertificateIssuerListResultPage, err error) {
	panic("not implemented")
}

func (m *mockApi) GetCertificateIssuersComplete(ctx context.Context, vaultBaseURL string, maxresults *int32) (result keyvault.CertificateIssuerListResultIterator, err error) {
	panic("not implemented")
}

func (m *mockApi) GetCertificateOperation(ctx context.Context, vaultBaseURL string, certificateName string) (result keyvault.CertificateOperation, err error) {
	panic("not implemented")
}

func (m *mockApi) GetCertificatePolicy(ctx context.Context, vaultBaseURL string, certificateName string) (result keyvault.CertificatePolicy, err error) {
	panic("not implemented")
}

func (m *mockApi) GetCertificates(ctx context.Context, vaultBaseURL string, maxresults *int32, includePending *bool) (result keyvault.CertificateListResultPage, err error) {
	panic("not implemented")
}

func (m *mockApi) GetCertificatesComplete(ctx context.Context, vaultBaseURL string, maxresults *int32, includePending *bool) (result keyvault.CertificateListResultIterator, err error) {
	panic("not implemented")
}

func (m *mockApi) GetCertificateVersions(ctx context.Context, vaultBaseURL string, certificateName string, maxresults *int32) (result keyvault.CertificateListResultPage, err error) {
	panic("not implemented")
}

func (m *mockApi) GetCertificateVersionsComplete(ctx context.Context, vaultBaseURL string, certificateName string, maxresults *int32) (result keyvault.CertificateListResultIterator, err error) {
	panic("not implemented")
}

func (m *mockApi) GetDeletedCertificate(ctx context.Context, vaultBaseURL string, certificateName string) (result keyvault.DeletedCertificateBundle, err error) {
	panic("not implemented")
}

func (m *mockApi) GetDeletedCertificates(ctx context.Context, vaultBaseURL string, maxresults *int32, includePending *bool) (result keyvault.DeletedCertificateListResultPage, err error) {
	panic("not implemented")
}

func (m *mockApi) GetDeletedCertificatesComplete(ctx context.Context, vaultBaseURL string, maxresults *int32, includePending *bool) (result keyvault.DeletedCertificateListResultIterator, err error) {
	panic("not implemented")
}

func (m *mockApi) GetDeletedKey(ctx context.Context, vaultBaseURL string, keyName string) (result keyvault.DeletedKeyBundle, err error) {
	panic("not implemented")
}

func (m *mockApi) GetDeletedKeys(ctx context.Context, vaultBaseURL string, maxresults *int32) (result keyvault.DeletedKeyListResultPage, err error) {
	panic("not implemented")
}

func (m *mockApi) GetDeletedKeysComplete(ctx context.Context, vaultBaseURL string, maxresults *int32) (result keyvault.DeletedKeyListResultIterator, err error) {
	panic("not implemented")
}

func (m *mockApi) GetDeletedSasDefinition(ctx context.Context, vaultBaseURL string, storageAccountName string, sasDefinitionName string) (result keyvault.DeletedSasDefinitionBundle, err error) {
	panic("not implemented")
}

func (m *mockApi) GetDeletedSasDefinitions(ctx context.Context, vaultBaseURL string, storageAccountName string, maxresults *int32) (result keyvault.DeletedSasDefinitionListResultPage, err error) {
	panic("not implemented")
}

func (m *mockApi) GetDeletedSasDefinitionsComplete(ctx context.Context, vaultBaseURL string, storageAccountName string, maxresults *int32) (result keyvault.DeletedSasDefinitionListResultIterator, err error) {
	panic("not implemented")
}

func (m *mockApi) GetDeletedSecret(ctx context.Context, vaultBaseURL string, secretName string) (result keyvault.DeletedSecretBundle, err error) {
	panic("not implemented")
}

func (m *mockApi) GetDeletedSecrets(ctx context.Context, vaultBaseURL string, maxresults *int32) (result keyvault.DeletedSecretListResultPage, err error) {
	panic("not implemented")
}

func (m *mockApi) GetDeletedSecretsComplete(ctx context.Context, vaultBaseURL string, maxresults *int32) (result keyvault.DeletedSecretListResultIterator, err error) {
	panic("not implemented")
}

func (m *mockApi) GetDeletedStorageAccount(ctx context.Context, vaultBaseURL string, storageAccountName string) (result keyvault.DeletedStorageBundle, err error) {
	panic("not implemented")
}

func (m *mockApi) GetDeletedStorageAccounts(ctx context.Context, vaultBaseURL string, maxresults *int32) (result keyvault.DeletedStorageListResultPage, err error) {
	panic("not implemented")
}

func (m *mockApi) GetDeletedStorageAccountsComplete(ctx context.Context, vaultBaseURL string, maxresults *int32) (result keyvault.DeletedStorageListResultIterator, err error) {
	panic("not implemented")
}

func (m *mockApi) GetKey(ctx context.Context, vaultBaseURL string, keyName string, keyVersion string) (result keyvault.KeyBundle, err error) {
	panic("not implemented")
}

func (m *mockApi) GetKeys(ctx context.Context, vaultBaseURL string, maxresults *int32) (result keyvault.KeyListResultPage, err error) {
	panic("not implemented")
}

func (m *mockApi) GetKeysComplete(ctx context.Context, vaultBaseURL string, maxresults *int32) (result keyvault.KeyListResultIterator, err error) {
	panic("not implemented")
}

func (m *mockApi) GetKeyVersions(ctx context.Context, vaultBaseURL string, keyName string, maxresults *int32) (result keyvault.KeyListResultPage, err error) {
	panic("not implemented")
}

func (m *mockApi) GetKeyVersionsComplete(ctx context.Context, vaultBaseURL string, keyName string, maxresults *int32) (result keyvault.KeyListResultIterator, err error) {
	panic("not implemented")
}

func (m *mockApi) GetSasDefinition(ctx context.Context, vaultBaseURL string, storageAccountName string, sasDefinitionName string) (result keyvault.SasDefinitionBundle, err error) {
	panic("not implemented")
}

func (m *mockApi) GetSasDefinitions(ctx context.Context, vaultBaseURL string, storageAccountName string, maxresults *int32) (result keyvault.SasDefinitionListResultPage, err error) {
	panic("not implemented")
}

func (m *mockApi) GetSasDefinitionsComplete(ctx context.Context, vaultBaseURL string, storageAccountName string, maxresults *int32) (result keyvault.SasDefinitionListResultIterator, err error) {
	panic("not implemented")
}

func (m *mockApi) GetSecret(ctx context.Context, vaultBaseURL string, secretName string, secretVersion string) (result keyvault.SecretBundle, err error) {
	panic("not implemented")
}

func (m *mockApi) GetSecrets(ctx context.Context, vaultBaseURL string, maxresults *int32) (result keyvault.SecretListResultPage, err error) {
	panic("not implemented")
}

func (m *mockApi) GetSecretsComplete(ctx context.Context, vaultBaseURL string, maxresults *int32) (result keyvault.SecretListResultIterator, err error) {
	panic("not implemented")
}

func (m *mockApi) GetSecretVersions(ctx context.Context, vaultBaseURL string, secretName string, maxresults *int32) (result keyvault.SecretListResultPage, err error) {
	panic("not implemented")
}

func (m *mockApi) GetSecretVersionsComplete(ctx context.Context, vaultBaseURL string, secretName string, maxresults *int32) (result keyvault.SecretListResultIterator, err error) {
	panic("not implemented")
}

func (m *mockApi) GetStorageAccount(ctx context.Context, vaultBaseURL string, storageAccountName string) (result keyvault.StorageBundle, err error) {
	panic("not implemented")
}

func (m *mockApi) GetStorageAccounts(ctx context.Context, vaultBaseURL string, maxresults *int32) (result keyvault.StorageListResultPage, err error) {
	panic("not implemented")
}

func (m *mockApi) GetStorageAccountsComplete(ctx context.Context, vaultBaseURL string, maxresults *int32) (result keyvault.StorageListResultIterator, err error) {
	panic("not implemented")
}

func (m *mockApi) ImportCertificate(ctx context.Context, vaultBaseURL string, certificateName string, parameters keyvault.CertificateImportParameters) (result keyvault.CertificateBundle, err error) {
	panic("not implemented")
}

func (m *mockApi) ImportKey(ctx context.Context, vaultBaseURL string, keyName string, parameters keyvault.KeyImportParameters) (result keyvault.KeyBundle, err error) {
	panic("not implemented")
}

func (m *mockApi) MergeCertificate(ctx context.Context, vaultBaseURL string, certificateName string, parameters keyvault.CertificateMergeParameters) (result keyvault.CertificateBundle, err error) {
	panic("not implemented")
}

func (m *mockApi) PurgeDeletedCertificate(ctx context.Context, vaultBaseURL string, certificateName string) (result autorest.Response, err error) {
	panic("not implemented")
}

func (m *mockApi) PurgeDeletedKey(ctx context.Context, vaultBaseURL string, keyName string) (result autorest.Response, err error) {
	panic("not implemented")
}

func (m *mockApi) PurgeDeletedSecret(ctx context.Context, vaultBaseURL string, secretName string) (result autorest.Response, err error) {
	panic("not implemented")
}

func (m *mockApi) PurgeDeletedStorageAccount(ctx context.Context, vaultBaseURL string, storageAccountName string) (result autorest.Response, err error) {
	panic("not implemented")
}

func (m *mockApi) RecoverDeletedCertificate(ctx context.Context, vaultBaseURL string, certificateName string) (result keyvault.CertificateBundle, err error) {
	panic("not implemented")
}

func (m *mockApi) RecoverDeletedKey(ctx context.Context, vaultBaseURL string, keyName string) (result keyvault.KeyBundle, err error) {
	panic("not implemented")
}

func (m *mockApi) RecoverDeletedSasDefinition(ctx context.Context, vaultBaseURL string, storageAccountName string, sasDefinitionName string) (result keyvault.SasDefinitionBundle, err error) {
	panic("not implemented")
}

func (m *mockApi) RecoverDeletedSecret(ctx context.Context, vaultBaseURL string, secretName string) (result keyvault.SecretBundle, err error) {
	panic("not implemented")
}

func (m *mockApi) RecoverDeletedStorageAccount(ctx context.Context, vaultBaseURL string, storageAccountName string) (result keyvault.StorageBundle, err error) {
	panic("not implemented")
}

func (m *mockApi) RegenerateStorageAccountKey(ctx context.Context, vaultBaseURL string, storageAccountName string, parameters keyvault.StorageAccountRegenerteKeyParameters) (result keyvault.StorageBundle, err error) {
	panic("not implemented")
}

func (m *mockApi) RestoreCertificate(ctx context.Context, vaultBaseURL string, parameters keyvault.CertificateRestoreParameters) (result keyvault.CertificateBundle, err error) {
	panic("not implemented")
}

func (m *mockApi) RestoreKey(ctx context.Context, vaultBaseURL string, parameters keyvault.KeyRestoreParameters) (result keyvault.KeyBundle, err error) {
	panic("not implemented")
}

func (m *mockApi) RestoreSecret(ctx context.Context, vaultBaseURL string, parameters keyvault.SecretRestoreParameters) (result keyvault.SecretBundle, err error) {
	panic("not implemented")
}

func (m *mockApi) RestoreStorageAccount(ctx context.Context, vaultBaseURL string, parameters keyvault.StorageRestoreParameters) (result keyvault.StorageBundle, err error) {
	panic("not implemented")
}

func (m *mockApi) SetCertificateContacts(ctx context.Context, vaultBaseURL string, contacts keyvault.Contacts) (result keyvault.Contacts, err error) {
	panic("not implemented")
}

func (m *mockApi) SetCertificateIssuer(ctx context.Context, vaultBaseURL string, issuerName string, parameter keyvault.CertificateIssuerSetParameters) (result keyvault.IssuerBundle, err error) {
	panic("not implemented")
}

func (m *mockApi) SetSasDefinition(ctx context.Context, vaultBaseURL string, storageAccountName string, sasDefinitionName string, parameters keyvault.SasDefinitionCreateParameters) (result keyvault.SasDefinitionBundle, err error) {
	panic("not implemented")
}

func (m *mockApi) SetSecret(ctx context.Context, vaultBaseURL string, secretName string, parameters keyvault.SecretSetParameters) (result keyvault.SecretBundle, err error) {
	panic("not implemented")
}

func (m *mockApi) SetStorageAccount(ctx context.Context, vaultBaseURL string, storageAccountName string, parameters keyvault.StorageAccountCreateParameters) (result keyvault.StorageBundle, err error) {
	panic("not implemented")
}

func (m *mockApi) UnwrapKey(ctx context.Context, vaultBaseURL string, keyName string, keyVersion string, parameters keyvault.KeyOperationsParameters) (result keyvault.KeyOperationResult, err error) {
	panic("not implemented")
}

func (m *mockApi) UpdateCertificate(ctx context.Context, vaultBaseURL string, certificateName string, certificateVersion string, parameters keyvault.CertificateUpdateParameters) (result keyvault.CertificateBundle, err error) {
	panic("not implemented")
}

func (m *mockApi) UpdateCertificateIssuer(ctx context.Context, vaultBaseURL string, issuerName string, parameter keyvault.CertificateIssuerUpdateParameters) (result keyvault.IssuerBundle, err error) {
	panic("not implemented")
}

func (m *mockApi) UpdateCertificateOperation(ctx context.Context, vaultBaseURL string, certificateName string, certificateOperation keyvault.CertificateOperationUpdateParameter) (result keyvault.CertificateOperation, err error) {
	panic("not implemented")
}

func (m *mockApi) UpdateCertificatePolicy(ctx context.Context, vaultBaseURL string, certificateName string, certificatePolicy keyvault.CertificatePolicy) (result keyvault.CertificatePolicy, err error) {
	panic("not implemented")
}

func (m *mockApi) UpdateKey(ctx context.Context, vaultBaseURL string, keyName string, keyVersion string, parameters keyvault.KeyUpdateParameters) (result keyvault.KeyBundle, err error) {
	panic("not implemented")
}

func (m *mockApi) UpdateSasDefinition(ctx context.Context, vaultBaseURL string, storageAccountName string, sasDefinitionName string, parameters keyvault.SasDefinitionUpdateParameters) (result keyvault.SasDefinitionBundle, err error) {
	panic("not implemented")
}

func (m *mockApi) UpdateSecret(ctx context.Context, vaultBaseURL string, secretName string, secretVersion string, parameters keyvault.SecretUpdateParameters) (result keyvault.SecretBundle, err error) {
	panic("not implemented")
}

func (m *mockApi) UpdateStorageAccount(ctx context.Context, vaultBaseURL string, storageAccountName string, parameters keyvault.StorageAccountUpdateParameters) (result keyvault.StorageBundle, err error) {
	panic("not implemented")
}

func (m *mockApi) Verify(ctx context.Context, vaultBaseURL string, keyName string, keyVersion string, parameters keyvault.KeyVerifyParameters) (result keyvault.KeyVerifyResult, err error) {
	panic("not implemented")
}

func (m *mockApi) WrapKey(ctx context.Context, vaultBaseURL string, keyName string, keyVersion string, parameters keyvault.KeyOperationsParameters) (result keyvault.KeyOperationResult, err error) {
	panic("not implemented")
}

// #endregion unused keyvault api
