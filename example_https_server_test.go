package azkeyvault_test

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/tg123/azkeyvault"
)

func Example() {
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

	l, err := net.Listen("tcp", ":9000")
	if err != nil {
		log.Fatal(err)
	}

	cert, err := kv.Certificate()
	if err != nil {
		log.Fatal(err)
	}

	tlsconf := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{cert.Raw},
			PrivateKey:  kv,
		}},
	}

	netln := tls.NewListener(l, tlsconf)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello\n")
	})
	http.Serve(netln, nil)
}
