package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"flag"
	"log"
	"math/big"
	"net"
	"net/mail"
	"net/url"
	"os"
	"time"
)

// Pair holds the public certificate and the private key
type Pair struct {
	Cert *x509.Certificate
	Key  crypto.PrivateKey
}

var opts struct {
	rsa        bool
	ecdsa      bool
	ed25519    bool
	passphrase string
}

func newPair(name string, CA *Pair, altNames []string, client bool, passphrase string) {
	priv, pub := genPair()

	tpl := &x509.Certificate{
		SerialNumber: randomSerialNumber(),
		Subject: pkix.Name{
			Organization:       []string{"simplepki"},
			OrganizationalUnit: []string{"root@localhost"},
			CommonName:         name,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 1, 1), // One year, one month, one day
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	for _, h := range altNames {
		if ip := net.ParseIP(h); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else if email, err := mail.ParseAddress(h); err == nil && email.Address == h {
			tpl.EmailAddresses = append(tpl.EmailAddresses, h)
		} else if uriName, err := url.Parse(h); err == nil && uriName.Scheme != "" && uriName.Host != "" {
			tpl.URIs = append(tpl.URIs, uriName)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, h)
		}
	}

	if client {
		tpl.ExtKeyUsage = append(tpl.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	}
	if len(tpl.IPAddresses) > 0 || len(tpl.DNSNames) > 0 || len(tpl.URIs) > 0 {
		tpl.ExtKeyUsage = append(tpl.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	}
	if len(tpl.EmailAddresses) > 0 {
		tpl.ExtKeyUsage = append(tpl.ExtKeyUsage, x509.ExtKeyUsageEmailProtection)
	}

	cert, err := x509.CreateCertificate(rand.Reader, tpl, CA.Cert, pub, CA.Key)
	if err != nil {
		log.Fatal(err)
	}

	writeCert(name, cert)
	writeKey(name, priv, passphrase)
}

func genPair() (crypto.PrivateKey, any) {
	var priv any
	var err error

	if opts.ed25519 {
		_, priv, err = ed25519.GenerateKey(rand.Reader)
	} else if opts.rsa {
		priv, err = rsa.GenerateKey(rand.Reader, 4096)
	} else {
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		log.Fatal(err)
	}

	pub := priv.(crypto.Signer).Public()
	return priv, pub
}

func randomSerialNumber() *big.Int {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatal(err)
	}
	return serialNumber
}

func newCA(name string, CA *Pair, passphrase string) *Pair {
	priv, pub := genPair()

	spkiASN1, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		log.Fatal(err)
	}

	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	_, err = asn1.Unmarshal(spkiASN1, &spki)
	if err != nil {
		log.Fatal(err)
	}

	skid := sha1.Sum(spki.SubjectPublicKey.Bytes)

	maxPathLen := 0
	if CA == nil {
		maxPathLen++
	}

	tpl := &x509.Certificate{
		SerialNumber: randomSerialNumber(),
		Subject: pkix.Name{
			Organization:       []string{"simplepki"},
			OrganizationalUnit: []string{"root@localhost"},
			CommonName:         name,
		},
		SubjectKeyId:          skid[:],
		NotAfter:              time.Now().AddDate(1, 1, 1), // One year, one month, one day
		NotBefore:             time.Now(),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            maxPathLen,
		MaxPathLenZero:        maxPathLen == 0,
	}

	var cert []byte
	if CA != nil {
		cert, err = x509.CreateCertificate(rand.Reader, tpl, CA.Cert, pub, CA.Key)
	} else {
		cert, err = x509.CreateCertificate(rand.Reader, tpl, tpl, pub, priv)
	}
	if err != nil {
		log.Fatal(err)
	}

	writeCert(name, cert)
	writeKey(name, priv, passphrase)

	return &Pair{Key: priv, Cert: tpl}
}

func writeCert(name string, cert []byte) {
	certFile := name + ".pem"

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		log.Fatal(err)
	}
}

func writeKey(name string, priv crypto.PrivateKey, passphrase string) {
	keyFile := name + ".key"

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		log.Fatal(err)
	}

	var privPEM []byte

	if passphrase == "" {
		privPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	} else {
		block, err := x509.EncryptPEMBlock(rand.Reader, "PRIVATE KEY", privDER, []byte(passphrase), x509.PEMCipherAES256)
		if err != nil {
			log.Fatal(err)
		}
		privPEM = pem.EncodeToMemory(block)
	}

	if err := os.WriteFile(keyFile, privPEM, 0600); err != nil {
		log.Fatal(err)
	}
}

func init() {
	log.SetPrefix("ERROR: ")
	log.SetFlags(0)

	flag.BoolVar(&opts.rsa, "rsa", false, "Generate 4096-bits RSA keys")
	flag.BoolVar(&opts.ecdsa, "ecdsa", true, "Generate P-256 ECDSA keys")
	flag.BoolVar(&opts.ed25519, "ed25519", false, "Generate Ed25519 keys")
	flag.StringVar(&opts.passphrase, "pass", "", "Passphrase for keys")
	flag.Parse()
}

func main() {
	altNames := []string{"localhost", "127.0.0.1", "::1"}

	ca := newCA("ca", nil, opts.passphrase)
	subca := newCA("subca", ca, opts.passphrase)
	newPair("client", subca, altNames, true, opts.passphrase)
	newPair("server", subca, altNames, false, opts.passphrase)
}
