package azkeyvault_test

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
	"github.com/tg123/azkeyvault"
)

func Example_httpsServer() {
	// https server using azure keyvault
	vaultBaseURL := "https://<xxxx>.vault.azure.net/"
	keyName := "<key>"
	// config using client access key

	credential, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		panic(err)
	}

	keyClient, err := azkeys.NewClient(vaultBaseURL, credential, nil)
	if err != nil {
		panic(err)
	}

	certClient, err := azcertificates.NewClient(vaultBaseURL, credential, nil)
	if err != nil {
		panic(err)
	}

	kv, err := azkeyvault.NewSigner(keyClient, certClient, keyName, "")
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
