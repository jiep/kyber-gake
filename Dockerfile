FROM ubuntu:20.04

RUN apt update && \
  apt upgrade -y && \
  apt install -y cmake ninja-build libssl-dev

WORKDIR /kyber

COPY . .

RUN mkdir build-ninja && \
  cd build-ninja && \
  cmake -DBUILD_SHARED_LIBS=ON -GNinja .. && \
  ninja && ninja test

ENTRYPOINT ["/kyber/build-ninja/avx2/test_speed512-90s_avx2"]
