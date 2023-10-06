package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	source = flag.String("source", "", "Specify 'web' to read from web server or 'file' to read from disk")
	path   = flag.String("path", "", "The URL or file path to the PEM file")

	certExpiry = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "certificate_expiry_timestamp",
			Help: "The timestamp of when the certificate will expire.",
		},
		[]string{"issuer"},
	)
)

func init() {
	prometheus.MustRegister(certExpiry)
}

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
		updateCertExpiryMetric(cert)
	}

	http.Handle("/metrics", promhttp.Handler())
	err = http.ListenAndServe(":2112", nil)
	if err != nil {
		log.Fatal("Server failed to start:", err)
	}
}

func readFromWeb(url string) ([]byte, error) {
	client := &http.Client{}
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
	var block *pem.Block
	for {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		blocks = append(blocks, block.Bytes)
	}
	return blocks, nil
}

func updateCertExpiryMetric(cert *x509.Certificate) {
	issuer := cert.Issuer.CommonName
	if issuer == "" {
		issuer = "unknown"
	}
	certExpiry.With(prometheus.Labels{"issuer": issuer}).Set(float64(cert.NotAfter.Unix()))
}
