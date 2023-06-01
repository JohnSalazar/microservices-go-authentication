FROM golang:latest AS build

WORKDIR /build
ADD . .

RUN CGO_ENABLED=0 GOOS=linux \
    go build -ldflags '-extldflags "-static"' -o app

FROM scratch AS production
COPY /config/config-prod.json /config/config-prod.json
COPY --from=build /build/app /app

CMD ["./app", "-prod", "true"]