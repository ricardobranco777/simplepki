BIN	= simplepki

.PHONY: all
all:	$(BIN)

$(BIN): *.go
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -buildid=" -buildmode=pie

.PHONY: gen
gen:
	@rm -f go.mod go.sum
	@go mod init $(BIN)
	@go mod tidy

.PHONY: test
test: $(BIN)
	@go vet
	./$(BIN) -rsa
	@cat subca.pem ca.pem > cacerts.pem
	@openssl verify -x509_strict -purpose sslclient -CAfile cacerts.pem client.pem
	@openssl verify -x509_strict -purpose sslserver -CAfile cacerts.pem server.pem
	@openssl verify -x509_strict -CAfile cacerts.pem subca.pem
	@openssl x509 -text -noout -in client.pem | grep "^    Signature.Algorithm:"
	@rm -f *.key *.pem
	./$(BIN) -ecdsa
	@cat subca.pem ca.pem > cacerts.pem
	@openssl verify -x509_strict -purpose sslclient -CAfile cacerts.pem client.pem
	@openssl verify -x509_strict -purpose sslserver -CAfile cacerts.pem server.pem
	@openssl verify -x509_strict -CAfile cacerts.pem subca.pem
	@openssl x509 -text -noout -in client.pem | grep "^    Signature.Algorithm:"
	@rm -f *.key *.pem
	./$(BIN) -ed25519
	@cat subca.pem ca.pem > cacerts.pem
	@openssl verify -x509_strict -purpose sslclient -CAfile cacerts.pem client.pem
	@openssl verify -x509_strict -purpose sslserver -CAfile cacerts.pem server.pem
	@openssl verify -x509_strict -CAfile cacerts.pem subca.pem
	@openssl x509 -text -noout -in client.pem | grep "^    Signature.Algorithm:"
	@rm -f *.key *.pem

.PHONY: clean
clean:
	@go clean
	@rm -f *.pem *.key

euid    = $(shell id -u)
ifeq ($(euid),0)
BINDIR  = /usr/local/bin
else
BINDIR  = $(HOME)/bin
endif

.PHONY: install
install: $(BIN)
	@install -s -m 0755 $(BIN) $(BINDIR)

.PHONY: uninstall
uninstall:
	@rm -f $(BINDIR)/$(BIN)
