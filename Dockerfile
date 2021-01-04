FROM ubuntu:20.04 AS builder

RUN apt update && \
  apt upgrade -y && \
  apt install -y cmake libssl-dev

WORKDIR /build

COPY . .

RUN mkdir build && \
  cd build && \
  cmake -DCMAKE_BUILD_TYPE=Release .. && \
  make

FROM ubuntu:20.04

WORKDIR /kyber-gake

RUN mkdir -p avx2 ref
COPY --from=builder /build/build/avx2/test_gake* ./avx2/
COPY --from=builder /build/build/ref/test_gake* ./ref/
