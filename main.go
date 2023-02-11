package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	// "os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
)

type myCollector struct {
    metric *prometheus.Desc
}

func (c *myCollector) Describe(ch chan<- *prometheus.Desc) {
    ch <- c.metric
}

func (c *myCollector) Collect(ch chan<- prometheus.Metric) {
    // your logic should be placed here

    t := time.Date(2009, time.November, 10, 23, 0, 0, 12345678, time.UTC)
    s := prometheus.NewMetricWithTimestamp(t, prometheus.MustNewConstMetric(c.metric, prometheus.CounterValue, 123))

    ch <- s
}


func main() {

    // Running local http server to serve multiple x509 certificate stored in a file
    url := "http://localhost:8080/ca.pem"
    // url := os.Args[1]
    // fmt.Println(url)

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

// prom exporter

collector := &myCollector{
	metric: prometheus.NewDesc(
		"my_metric",
		"This is my metric with custom TS",
		nil,
		nil,
	),
}
prometheus.MustRegister(collector)

http.Handle("/metrics", promhttp.Handler())
// log.Info("Beginning to serve on port :8080")
http.ListenAndServe(":2112", nil)

}
