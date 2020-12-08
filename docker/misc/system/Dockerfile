FROM ubuntu:18.04

RUN useradd -ms /bin/bash coll

RUN apt-get update && apt-get install -y wget make build-essential gcc clang libbfd-dev libunwind-dev libipt-dev clang-4.0 binutils-dev git libtool libtool-bin automake bison libglib2.0-dev python python-pip cmake golang curl libc-ares-dev libfreetype6-dev libarchive-dev ragel bzip2 libgss-dev subversion libgcrypt-dev autoconf-archive virtualenv libdbus-glib-1-dev libgirepository1.0-dev libturbojpeg libssh-dev libssl-dev nasm libbz2-dev libxml2-dev
RUN pip install watchdog
RUN env python -m pip install watchdog

RUN echo "deb http://apt.llvm.org/bionic/ llvm-toolchain-bionic-9 main" >> /etc/apt/sources.list
RUN echo "deb-src http://apt.llvm.org/bionic/ llvm-toolchain-bionic-9 main" >> /etc/apt/sources.list
RUN apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 15CF4D18AF4F7421
RUN apt-get update
RUN apt-get install -y clang-9 llvm-9-dev lld-9 lld-9 clangd-9 lldb-9
RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-9 100
RUN update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-9 100
RUN update-alternatives --install /usr/bin/llvm-config llvm-config /usr/bin/llvm-config-9 100
RUN update-alternatives --install /usr/bin/lldb lldb /usr/bin/lldb-9 100

USER coll
WORKDIR /home/coll

RUN git clone https://github.com/google/fuzzer-test-suite.git && cd fuzzer-test-suite && git checkout b2e885706d63
COPY --chown=coll:coll misc/system/build.sh /home/coll/fuzzer-test-suite/
RUN ls -lah /home/coll/fuzzer-test-suite/
RUN chmod +x /home/coll/fuzzer-test-suite/build.sh

RUN wget http://panda.moyix.net/~moyix/lava_corpus.tar.xz && tar xfv lava_corpus.tar.xz

# install llvm / compiler-rt for libfuzzer

RUN wget http://releases.llvm.org/9.0.0/llvm-9.0.0.src.tar.xz -O llvm.tar.xz && tar xfv llvm.tar.xz
RUN wget http://releases.llvm.org/9.0.0/compiler-rt-9.0.0.src.tar.xz -O compiler-rt.tar.xz && ls -lah && tar xfv compiler-rt.tar.xz

RUN mkdir /home/coll/fuzzer-test-suite_seeds/
COPY --chown=coll:coll misc/data/fuzzer-test-suite_seeds/ /home/coll/fuzzer-test-suite_seeds/
RUN mkdir /home/coll/eval_seeds/
COPY --chown=coll:coll misc/data/eval_seeds/ /home/coll/eval_seeds/