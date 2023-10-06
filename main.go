package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"
)

var source = flag.String("source", "", "Specify 'web' to read from web server or 'file' to read from disk")
var path = flag.String("path", "", "The URL or file path to the PEM file")

func main() {
	flag.Parse()

	if *source == "" || *path == "" {
		log.Fatal("Both source and path flags are required")
	}

	var pemData []byte
	var err error

	switch *source {
	case "web":
		pemData, err = readFromWeb(*path)
	case "file":
		pemData, err = readFromFile(*path)
	default:
		log.Fatal("Invalid source. Specify 'web' or 'file'.")
	}

	if err != nil {
		log.Fatal(err)
	}

	pemBlocks, err := parsePEMBlocks(pemData)
	if err != nil {
		log.Fatal(err)
	}

	for _, block := range pemBlocks {
		cert, err := x509.ParseCertificate(block)
		if err != nil {
			log.Println(err)
			continue
		}
		printCertDetails(cert)
	}
}

func readFromWeb(url string) ([]byte, error) {
	client := &http.Client{
		Timeout: time.Second * 10,
	}

	response, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	return io.ReadAll(response.Body)
}

func readFromFile(filePath string) ([]byte, error) {
	return ioutil.ReadFile(filePath)
}

func parsePEMBlocks(data []byte) ([][]byte, error) {
	var blocks [][]byte
	rest := data
	for {
		block, rest := pem.Decode(rest)
		if block == nil {
			if len(rest) > 0 {
				return nil, fmt.Errorf("remainder of data contains invalid PEM block: %s", string(rest))
			}
			break
		}
		blocks = append(blocks, block.Bytes)
	}
	return blocks, nil
}

func printCertDetails(cert *x509.Certificate) {
	fmt.Printf("\tSubject: %+v\n", cert.Issuer)
	fmt.Printf("\tNotafter %+v\n", cert.NotAfter)
	fmt.Printf("\tNotAfterUnix: %d\n", cert.NotAfter.Unix())
}
