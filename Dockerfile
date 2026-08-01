FROM golang:1.23-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/shinkai-shoujo ./cmd/shinkai-shoujo

FROM alpine:3.20
RUN apk add --no-cache ca-certificates && addgroup -S shinkai && adduser -S -G shinkai shinkai
COPY --from=build /out/shinkai-shoujo /usr/local/bin/shinkai-shoujo
USER shinkai
ENTRYPOINT ["shinkai-shoujo"]
CMD ["daemon", "--config", "/etc/shinkai/config.yaml"]
