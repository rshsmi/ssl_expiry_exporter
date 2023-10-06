# ssl_expiry_exporter

expose exipry date of a x509 certificate stored in a file on disk or a web file server. Use case for this exporter is to monitor internal CA which organisations generate and distribute for devs.

go run main.go -source=file -path=./cert.pem

go run main.go -source=web -path=http://localhost:8080/cert.pem
