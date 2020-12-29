FROM ubuntu:20.04

RUN apt update && \
  apt upgrade -y && \
  apt install -y cmake ninja-build libssl-dev inotify-tools

WORKDIR /kyber

COPY monitor-and-compile.sh .

# RUN mkdir build && \
#   cd build && \
#   cmake -GNinja -DCMAKE_BUILD_TYPE=Release .. && \
#   ninja && ninja test

CMD ["bash", "monitor-and-compile.sh"]
# CMD ["/kyber/build/avx2/test_speed512-90s_avx2"]
