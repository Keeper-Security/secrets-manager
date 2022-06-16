SHELL := /bin/bash

NAME = $(PLUGIN_NAME)
VERSION = $(PLUGIN_VERSION)
KEY = $(SIGNING_KEY)
PASSPHRASE = $(KEY_PASSPHRASE)

all: fmt build

fmt:
	go fmt $$(go list ./...)

test:
	go test ./...

test/coverage:
	go test -v ./... -cover

build:
	go build

release:
	go build; zip -m ${NAME}.zip ${NAME} ${NAME}.exe

release-all: release-other release-win-x86 release-win-x64 release-checksum drop-keys

release-other:
	$(eval GOOS=darwin)  $(eval GOARCH=amd64) GOOS=${GOOS} GOARCH=${GOARCH} go build -o ${NAME} ; zip -m ${NAME}_${VERSION}_${GOOS}_${GOARCH}.zip ${NAME}
	$(eval GOOS=darwin)  $(eval GOARCH=arm64) GOOS=${GOOS} GOARCH=${GOARCH} go build -o ${NAME} ; zip -m ${NAME}_${VERSION}_${GOOS}_${GOARCH}.zip ${NAME}
	$(eval GOOS=freebsd) $(eval GOARCH=386)   GOOS=${GOOS} GOARCH=${GOARCH} go build -o ${NAME} ; zip -m ${NAME}_${VERSION}_${GOOS}_${GOARCH}.zip ${NAME}
	$(eval GOOS=freebsd) $(eval GOARCH=amd64) GOOS=${GOOS} GOARCH=${GOARCH} go build -o ${NAME} ; zip -m ${NAME}_${VERSION}_${GOOS}_${GOARCH}.zip ${NAME}
	$(eval GOOS=freebsd) $(eval GOARCH=arm)   GOOS=${GOOS} GOARCH=${GOARCH} go build -o ${NAME} ; zip -m ${NAME}_${VERSION}_${GOOS}_${GOARCH}.zip ${NAME}
	$(eval GOOS=linux)   $(eval GOARCH=386)   GOOS=${GOOS} GOARCH=${GOARCH} go build -o ${NAME} ; zip -m ${NAME}_${VERSION}_${GOOS}_${GOARCH}.zip ${NAME}
	$(eval GOOS=linux)   $(eval GOARCH=amd64) GOOS=${GOOS} GOARCH=${GOARCH} go build -o ${NAME} ; zip -m ${NAME}_${VERSION}_${GOOS}_${GOARCH}.zip ${NAME}
	$(eval GOOS=linux)   $(eval GOARCH=arm)   GOOS=${GOOS} GOARCH=${GOARCH} go build -o ${NAME} ; zip -m ${NAME}_${VERSION}_${GOOS}_${GOARCH}.zip ${NAME}
	$(eval GOOS=linux)   $(eval GOARCH=arm64) GOOS=${GOOS} GOARCH=${GOARCH} go build -o ${NAME} ; zip -m ${NAME}_${VERSION}_${GOOS}_${GOARCH}.zip ${NAME}

release-win-x86: gen-keys
	$(eval GOOS=windows) $(eval GOARCH=386)   GOOS=${GOOS} GOARCH=${GOARCH} go build -o ${NAME}.exe
	if [[ -s ks.spc && -s ks.key ]]; then \
		osslsigncode sign -spc ks.spc -key ks.key -n "Vault Plugin Secrets KSM" -i "https://keepersecurity.com" -t "http://timestamp.digicert.com" -in ${NAME}.exe -out ${NAME}_signed.exe ; \
		[[ -s ${NAME}_signed.exe ]] && mv -f ${NAME}_signed.exe ${NAME}.exe && echo "Signed release-win-x86" ; \
	fi
	zip -m ${NAME}_${VERSION}_${GOOS}_${GOARCH}.zip ${NAME}.exe

release-win-x64: gen-keys
	$(eval GOOS=windows) $(eval GOARCH=amd64) GOOS=${GOOS} GOARCH=${GOARCH} go build -o ${NAME}.exe
	if [[ -s ks.spc && -s ks.key ]]; then \
		osslsigncode sign -spc ks.spc -key ks.key -n "Vault Plugin Secrets KSM" -i "https://keepersecurity.com" -t "http://timestamp.digicert.com" -in ${NAME}.exe -out ${NAME}_signed.exe ; \
		[[ -s ${NAME}_signed.exe ]] && mv -f ${NAME}_signed.exe ${NAME}.exe && echo "Signed release-win-x64" ; \
	fi
	zip -m ${NAME}_${VERSION}_${GOOS}_${GOARCH}.zip ${NAME}.exe

gen-keys:
	if [[ -n "${KEY}" ]]; then \
		openssl pkcs12 -in ${KEY} -nocerts -nodes -out key.pem  -passin pass:${PASSPHRASE} ; \
		openssl pkcs12 -in ${KEY}          -nodes -out cert.pem -passin pass:${PASSPHRASE} ; \
		openssl rsa -in key.pem -outform DER -out ks.key ; \
		openssl crl2pkcs7 -nocrl -certfile cert.pem -outform DER -out ks.spc ; \
	fi

release-checksum:
	sha256sum ${NAME}_${VERSION}_*.zip > ${NAME}_${VERSION}_SHA256SUMS

drop-keys:
	rm -f ${KEY}
	rm -f key.pem
	rm -f cert.pem
	rm -f ks.key
	rm -f ks.spc
