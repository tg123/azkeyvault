# Signer and Decrypter for Azure KeyVault
[![](https://pkg.go.dev/badge/github.com/tg123/azkeyvault?status.svg)](https://pkg.go.dev/github.com/tg123/azkeyvault/v2)

This Go package wraps Azure KeyVault, [sign](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/sign/sign) and [decrypt](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/decrypt/decrypt), into Golang crypto.Signer and crypto.Decrypter. 
The private key is protected by Azure KeyVault and no direct access from app.

## Examples

[HTTPS Server](example_https_server_test.go)

[SSH Client](example_ssh_client_test.go)

## Permissions required

 Keep minimal permision to protect the private keys. No extra permission required if API is not in use.

 * Public() keys/get
 * Signer.Sign() keys/sign
 * Decrypter.Decrypt() keys/decrypt
