package azkeyvault_test

import (
	"bytes"
	"fmt"
	"log"
	"strings"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"golang.org/x/crypto/ssh"
)

func ExampleSshClient() {
	// https server using azure keyvault

	// config using client access key
	clientID := "<client id>"
	clientSecret := "<client secret>"
	tenantID := "<tenant id>"

	vaultBaseURL := "https://<xxxx>.vault.azure.net/"
	keyName := "<key>"
	// config using client access key

	config := auth.NewClientCredentialsConfig(clientID, clientSecret, tenantID)
	config.Resource = "https://vault.azure.net"

	a, err := config.Authorizer()
	if err != nil {
		panic(err)
	}

	basicClient := keyvault.New()
	basicClient.Authorizer = a

	kv, err := azkeyvault.NewSigner(basicClient, vaultBaseURL, keyName, "")
	if err != nil {
		panic(err)
	}

	signer, err := ssh.NewSignerFromSigner(kv)
	if err != nil {
		panic(err)
	}

	fmt.Printf(`echo "%s" >> /root/.ssh/authorized_keys`, strings.Trim(string(ssh.MarshalAuthorizedKey(signer.PublicKey())), "\n"))
	fmt.Println()

	client, err := ssh.Dial("tcp", "127.0.0.1:22", &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		log.Fatal("Failed to dial: ", err)
	}
	defer client.Close()

	// Each ClientConn can support multiple interactive sessions,
	// represented by a Session.
	session, err := client.NewSession()
	if err != nil {
		log.Fatal("Failed to create session: ", err)
	}
	defer session.Close()

	// Once a Session is created, you can execute a single command on
	// the remote side using the Run method.
	var b bytes.Buffer
	session.Stdout = &b
	if err := session.Run("/usr/bin/whoami"); err != nil {
		log.Fatal("Failed to run: " + err.Error())
	}
	fmt.Println(b.String())
}
