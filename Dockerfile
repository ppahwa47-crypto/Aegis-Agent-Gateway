FROM golang:1.27.2-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/aegis ./cmd/aegis

FROM alpine:3.22
RUN addgroup -g 10001 aegis && adduser -D -u 10001 -G aegis aegis
COPY --from=build /out/aegis /usr/local/bin/aegis
USER 10001:10001
EXPOSE 8080 8090
ENTRYPOINT ["aegis"]
CMD ["gateway"]
