GOLANGCI_VERSION = "v1.61.0"

all: lint test

lint: .golangci
	golangci-lint -v run

.golangci:
	which golangci-lint > /dev/null \
		&& (echo 'golangci-lint version:'; golangci-lint --version) \
		|| curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh \
		| sh -s -- -b ${GOPATH}/bin ${GOLANGCI_VERSION}

test:
	go test ./...

cover:
	COVER_FILE="profile.cov"
	go test -coverpkg=./internal/... -coverprofile=$COVER_FILE ./...
	go tool cover -func $COVER_FILE
	@[[ -f $COVER_FILE ]] && rm $COVER_FILE
