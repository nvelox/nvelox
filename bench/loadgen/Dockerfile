# syntax=docker/dockerfile:1
# The load generators of the benchmark kit: wrk 4.1.0 (the Debian package) for HTTP/1.1, HTTPS and
# TCP, and h2load from nghttp2 1.71.0 for HTTP/2 and HTTP/3. h2load is built here with ngtcp2 1.26.0
# and nghttp3 1.19.0, because the packaged h2load is linked without them and speaks no HTTP/3.
# The release tarballs are pinned by checksum.
FROM debian:trixie-slim AS build
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential pkg-config libssl-dev libev-dev libc-ares-dev zlib1g-dev xz-utils ca-certificates
ADD --checksum=sha256:228e17f5cc3d4de7bfced9912bd09de30e7f45741cc47503cf88d3fa9209e155 \
    https://github.com/ngtcp2/nghttp3/releases/download/v1.19.0/nghttp3-1.19.0.tar.xz /src/
ADD --checksum=sha256:7804aa0fa1c39942ba322a90805824c37231f7675b08d0c3cc4332858a7b085e \
    https://github.com/ngtcp2/ngtcp2/releases/download/v1.26.0/ngtcp2-1.26.0.tar.xz /src/
ADD --checksum=sha256:c0f55121d88650e4b9227aec28cebaf664d2417ca60fe70be0f8d38829f52116 \
    https://github.com/nghttp2/nghttp2/releases/download/v1.71.0/nghttp2-1.71.0.tar.xz /src/
WORKDIR /src
RUN for f in *.tar.xz; do tar -xJf "$f"; done
ENV PKG_CONFIG_PATH=/opt/h2/lib/pkgconfig
RUN cd nghttp3-1.19.0 && ./configure --prefix=/opt/h2 --enable-lib-only && make -j"$(nproc)" && make install
RUN cd ngtcp2-1.26.0 && ./configure --prefix=/opt/h2 --enable-lib-only --with-openssl && make -j"$(nproc)" && make install
RUN cd nghttp2-1.71.0 && ./configure --prefix=/opt/h2 --enable-app --enable-http3 \
      --with-libngtcp2 --with-libnghttp3 --disable-examples --disable-hpack-tools \
 && make -j"$(nproc)" && make install

FROM debian:trixie-slim
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      wrk curl openssl ca-certificates libssl3t64 libev4t64 libc-ares2 zlib1g procps iproute2 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /opt/h2 /opt/h2
ENV PATH=/opt/h2/bin:$PATH LD_LIBRARY_PATH=/opt/h2/lib
