FROM alpine:3.22.2 AS builder

RUN apk add --no-cache build-base linux-headers openssl-dev util-linux-dev

COPY . /src
WORKDIR /src

RUN make release

FROM alpine:3.22.2

RUN apk add --no-cache libuuid

COPY --from=builder /src/build/fise /bin/fise

CMD ["/bin/fise"]

LABEL org.opencontainers.image.source=https://github.com/PixelFederico/fise
LABEL org.opencontainers.image.description="File Server over HTTP"
LABEL org.opencontainers.image.licenses=MIT