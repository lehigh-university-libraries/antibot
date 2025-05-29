FROM golang:1.24-alpine3.21@sha256:ef18ee7117463ac1055f5a370ed18b8750f01589f13ea0b48642f5792b234044

WORKDIR /app

RUN adduser -S -G nobody antibot

COPY --chown=antibot:antibot . ./

RUN apk add --no-cache curl && \
  go mod download && \
  go build -o /app/antibot && \
  go clean -cache -modcache

USER antibot

ENTRYPOINT ["/app/antibot"]

HEALTHCHECK CMD curl -s http://localhost:8888/healthcheck
