# Signer and Decrypter for Azure KeyVault
[![](https://pkg.go.dev/badge/github.com/tg123/azkeyvault?status.svg)](https://pkg.go.dev/github.com/tg123/azkeyvault)

This Go package wraps Azure KeyVault, [sign](https://docs.microsoft.com/en-us/rest/api/keyvault/sign) and [decrypt](https://docs.microsoft.com/en-us/rest/api/keyvault/decrypt/decrypt), into Golang crypto.Signer and crypto.Decrypter. 
The private key is protected by Azure KeyVault and no direct access from app.

## Examples

[HTTPS server](https://github.com/tg123/azkeyvault/blob/main/example_https_server_test.go#L15)

## Permissions required

 Keep minimal permision to protect the private keys. No extra permission required if API is not in use.

 * Public() certificates/get
 * Signer.Sign() keys/sign
 * Decrypter.Decrypt() keys/decrypt
