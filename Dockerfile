FROM golang:1.20-alpine as builder

# Setup
RUN mkdir -p /go/src/github.com/sanderPostma/traefik-validate-jwt
WORKDIR /go/src/github.com/sanderPostma/traefik-validate-jwt

# Add libraries
RUN apk add --no-cache git

# Copy & build
ADD . /go/src/github.com/sanderPostma/traefik-validate-jwt
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -a -installsuffix nocgo -o /sanderPostma/traefik-validate-jwt/cmd

# Copy into scratch container
FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /traefik-validate-jwt ./
ENTRYPOINT ["./traefik-validate-jwt"]