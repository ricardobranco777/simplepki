![Build Status](https://github.com/ricardobranco777/simplepki/actions/workflows/ci.yml/badge.svg)

# simplepki

Simple PKI to test TLS applications

## Usage

```
Usage: simplepki [OPTIONS...]
  -ecdsa
    	Generate P-256 ECDSA keys (default true)
  -ed25519
    	Generate Ed25519 keys
  -pass string
    	Passphrase for keys
  -rsa
    	Generate 4096-bits RSA keys
```

The output is:
- `ca.key` (private key for root CA)
- `ca.pem` (certificate for root CA)
- `subca.key` (private key for intermediate CA)
- `subca.pem` (certificate for intermediate CA)
- `server.pem` (server certificate for localhost)
- `server.key` (private key for server)
- `client.pem` (client certificate for localhost)
- `client.key` (private key for client)

## Requirements

- Go >= 1.18

## Notes:

Python version: https://github.com/ricardobranco777/py-simplepki
