package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"log"
)

func main() {

	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	asn1, err := x509.MarshalECPrivateKey(pk)
	if err != nil {
		panic(err)
	}
	pkix, err := x509.MarshalPKIXPublicKey(pk.Public())
	if err != nil {
		panic(err)
	}
	v := base64.StdEncoding.EncodeToString(asn1)
	log.Printf("Private: %s", v)
	v = base64.StdEncoding.EncodeToString(pkix)
	log.Printf("Public:  %s", v)

}
