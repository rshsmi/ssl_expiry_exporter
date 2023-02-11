package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

func main() {
	url := "http://localhost:8080/ca.pem"
	response, err := http.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	defer response.Body.Close()

	responseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatal(err)
	}

	responseString := string(responseData)

	// fmt.Println(responseString)

	var pemData = []byte(responseString)
	var blocks [][]byte
	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			fmt.Printf("Error: PEM not parsed\n")
			break
		}
		blocks = append(blocks, block.Bytes)
		if len(rest) == 0 {
			break
		}
	}
	for _, block := range blocks {
		cert, err := x509.ParseCertificate(block)
		if err != nil {
			log.Println(err)
			continue
		}
		// fmt.Println("Certificate:")
		fmt.Printf("\tSubject: %+v\n", cert.Issuer)
		fmt.Printf("\tNotafter %+v\n", cert.NotAfter)
		fmt.Println("\tNotAfterUnix:", cert.NotAfter.Unix())

		// fmt.Printf("\tDNS Names: %+v\n", cert.DNSNames)
		// fmt.Printf("\tEmailAddresses: %+v\n", cert.EmailAddresses)
		// fmt.Printf("\tIPAddresses: %+v\n", cert.IPAddresses)
	}
}
