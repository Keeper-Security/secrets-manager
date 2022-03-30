PLUGIN_NAME = vault-plugin-secrets-ksm
versionFile = $(CURDIR)/.VERSION
VERSION := $(shell cat $(versionFile) | sed 's/^v//')

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
	go build; zip -m ${PLUGIN_NAME}.zip ${PLUGIN_NAME} ${PLUGIN_NAME}.exe

release-all:
	$(eval GOOS=darwin)  $(eval GOARCH=amd64) GOOS=${GOOS} GOARCH=${GOARCH} go build ; zip -m ${PLUGIN_NAME}_${VERSION}_${GOOS}_${GOARCH}.zip ${PLUGIN_NAME}
	$(eval GOOS=darwin)  $(eval GOARCH=arm64) GOOS=${GOOS} GOARCH=${GOARCH} go build ; zip -m ${PLUGIN_NAME}_${VERSION}_${GOOS}_${GOARCH}.zip ${PLUGIN_NAME}
	$(eval GOOS=freebsd) $(eval GOARCH=386)   GOOS=${GOOS} GOARCH=${GOARCH} go build ; zip -m ${PLUGIN_NAME}_${VERSION}_${GOOS}_${GOARCH}.zip ${PLUGIN_NAME}
	$(eval GOOS=freebsd) $(eval GOARCH=amd64) GOOS=${GOOS} GOARCH=${GOARCH} go build ; zip -m ${PLUGIN_NAME}_${VERSION}_${GOOS}_${GOARCH}.zip ${PLUGIN_NAME}
	$(eval GOOS=freebsd) $(eval GOARCH=arm)   GOOS=${GOOS} GOARCH=${GOARCH} go build ; zip -m ${PLUGIN_NAME}_${VERSION}_${GOOS}_${GOARCH}.zip ${PLUGIN_NAME}
	$(eval GOOS=linux)   $(eval GOARCH=386)   GOOS=${GOOS} GOARCH=${GOARCH} go build ; zip -m ${PLUGIN_NAME}_${VERSION}_${GOOS}_${GOARCH}.zip ${PLUGIN_NAME}
	$(eval GOOS=linux)   $(eval GOARCH=amd64) GOOS=${GOOS} GOARCH=${GOARCH} go build ; zip -m ${PLUGIN_NAME}_${VERSION}_${GOOS}_${GOARCH}.zip ${PLUGIN_NAME}
	$(eval GOOS=linux)   $(eval GOARCH=arm)   GOOS=${GOOS} GOARCH=${GOARCH} go build ; zip -m ${PLUGIN_NAME}_${VERSION}_${GOOS}_${GOARCH}.zip ${PLUGIN_NAME}
	$(eval GOOS=linux)   $(eval GOARCH=arm64) GOOS=${GOOS} GOARCH=${GOARCH} go build ; zip -m ${PLUGIN_NAME}_${VERSION}_${GOOS}_${GOARCH}.zip ${PLUGIN_NAME}
	$(eval GOOS=windows) $(eval GOARCH=386)   GOOS=${GOOS} GOARCH=${GOARCH} go build ; zip -m ${PLUGIN_NAME}_${VERSION}_${GOOS}_${GOARCH}.zip ${PLUGIN_NAME}.exe
	$(eval GOOS=windows) $(eval GOARCH=amd64) GOOS=${GOOS} GOARCH=${GOARCH} go build ; zip -m ${PLUGIN_NAME}_${VERSION}_${GOOS}_${GOARCH}.zip ${PLUGIN_NAME}.exe
	sha256sum ${PLUGIN_NAME}_${VERSION}_*.zip > ${PLUGIN_NAME}_${VERSION}_SHA256SUMS
