BIN	= simplepki

GO	:= go

# https://github.com/golang/go/issues/64875
arch := $(shell uname -m)
ifeq ($(arch),s390x)
CGO_ENABLED := 1
else
CGO_ENABLED ?= 0
endif

$(BIN): *.go
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build -trimpath -ldflags="-s -w -buildid=" -buildmode=pie

.PHONY: all
all:	$(BIN)

.PHONY: gen
gen:
	rm -f go.mod go.sum
	$(GO) mod init github.com/ricardobranco777/$(BIN)
	$(GO) mod tidy

.PHONY: test
test: $(BIN)
	$(GO) vet
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
	$(GO) clean
	rm -f *.pem *.key

euid    = $(shell id -u)
ifeq ($(euid),0)
BINDIR  = /usr/local/bin
else
BINDIR  = $(HOME)/bin
endif

.PHONY: install
install: $(BIN)
	install -s -m 0755 $(BIN) $(BINDIR)

.PHONY: uninstall
uninstall:
	rm -f $(BINDIR)/$(BIN)
