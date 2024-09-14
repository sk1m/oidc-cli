FROM golang:1.23-alpine AS build

ENV GO111MODULE=on
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download -x

COPY cmd cmd
COPY internal internal

RUN go build -v -ldflags "-s -w" -o /bin ./cmd/...


FROM alpine:latest

COPY --from=build /bin/oidc /bin/

ENTRYPOINT ["oidc"]
