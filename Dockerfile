FROM alpine:3.22.2 AS builder

RUN apk add --no-cache gcc musl-dev linux-headers openssl-dev openssl-libs-static util-linux-dev util-linux-static

COPY main.c /src/main.c

RUN gcc -Wall -W -O2 -static /src/main.c -luuid -lcrypto -o /bin/fise

FROM alpine:3.22.2

COPY --from=builder /bin/fise /bin/fise

CMD ["/bin/fise"]

LABEL org.opencontainers.image.source=https://github.com/PixelFederico/fise
LABEL org.opencontainers.image.description="File Server over HTTP"
LABEL org.opencontainers.image.licenses=MIT