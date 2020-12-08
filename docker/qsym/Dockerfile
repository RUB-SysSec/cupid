FROM qsym-base

RUN useradd -ms /bin/bash coll

RUN apt-get update && apt-get install -y wget make build-essential gcc clang libbfd-dev libunwind-dev clang-4.0 binutils-dev git libtool libtool-bin automake bison libglib2.0-dev python python-pip wget make build-essential gcc clang libbfd-dev libunwind-dev clang-4.0 binutils-dev git libtool libtool-bin automake bison libglib2.0-dev python python-pip cmake golang curl libc-ares-dev libfreetype6-dev libarchive-dev ragel bzip2 libgss-dev subversion libgcrypt-dev autoconf-archive virtualenv libdbus-glib-1-dev libgirepository1.0-dev libturbojpeg libssh-dev libssl-dev nasm libbz2-dev libxml2-dev lzma-dev liblzma-dev

USER coll
WORKDIR /home/coll

RUN wget https://ftp.gnu.org/gnu/binutils/binutils-2.31.1.tar.gz && tar xfv binutils-2.31.1.tar.gz

# install AFL
RUN wget http://lcamtuf.coredump.cx/afl/releases/afl-2.52b.tgz && tar xfv afl-2.52b.tgz && cd afl-2.52b && make -j && ls && ./afl-clang --version

# build binutils 
ARG CC=/home/coll/afl-2.52b/afl-gcc
ARG CXX=/home/coll/afl-2.52b/afl-g++
RUN cd binutils-2.31.1/ && ./configure && make -j

RUN mkdir uninstrumented

# build uninstrumented binutils
RUN tar xfv binutils-2.31.1.tar.gz -C uninstrumented
ARG CC=gcc
ARG CXX=g++
RUN cd uninstrumented/binutils-2.31.1/ && ./configure && make -j

ARG CC=
ARG CXX=

# get fuzzer-test-suite
RUN git clone https://github.com/google/fuzzer-test-suite.git && cd fuzzer-test-suite && git checkout b2e885706d63
COPY --chown=coll:coll misc/system/build.sh /home/coll/fuzzer-test-suite/
RUN ls -lah /home/coll/fuzzer-test-suite/
RUN chmod +x /home/coll/fuzzer-test-suite/build.sh

# build LAVA-M
RUN wget http://panda.moyix.net/~moyix/lava_corpus.tar.xz && tar xfv lava_corpus.tar.xz
RUN cd ~; cd lava_corpus/LAVA-M/base64/coreutils-8.24-lava-safe/ && ./configure CC=/home/coll/afl-2.52b/afl-gcc CXX=/home/coll/afl-2.52b/afl-g++ && make -j
RUN cd ~; cd lava_corpus/LAVA-M/md5sum/coreutils-8.24-lava-safe/ && ./configure CC=/home/coll/afl-2.52b/afl-gcc CXX=/home/coll/afl-2.52b/afl-g++ && make -j
RUN cd ~; cd lava_corpus/LAVA-M/uniq/coreutils-8.24-lava-safe/ && ./configure CC=/home/coll/afl-2.52b/afl-gcc CXX=/home/coll/afl-2.52b/afl-g++ && make -j
RUN cd ~; cd lava_corpus/LAVA-M/who/coreutils-8.24-lava-safe/ && ./configure CC=/home/coll/afl-2.52b/afl-gcc CXX=/home/coll/afl-2.52b/afl-g++ && make -j

# build uninstrumented LAVA-M
RUN tar xfv lava_corpus.tar.xz -C uninstrumented
RUN cd ~; cd uninstrumented/lava_corpus/LAVA-M/base64/coreutils-8.24-lava-safe/ && ./configure && make -j
RUN cd ~; cd uninstrumented/lava_corpus/LAVA-M/md5sum/coreutils-8.24-lava-safe/ && ./configure && make -j
RUN cd ~; cd uninstrumented/lava_corpus/LAVA-M/uniq/coreutils-8.24-lava-safe/   && ./configure && make -j
RUN cd ~; cd uninstrumented/lava_corpus/LAVA-M/who/coreutils-8.24-lava-safe/    && ./configure && make -j

# copy uninstrumented fuzzer-test-suite
RUN mkdir -p /home/coll/uninstrumented/fuzzer-test-suite
COPY --chown=coll:coll misc/system/fuzzer-test-suite_uninstrumented/* /home/coll/uninstrumented/fuzzer-test-suite/

# install llvm / compiler-rt for libfuzzer

RUN wget http://releases.llvm.org/9.0.0/llvm-9.0.0.src.tar.xz -O llvm.tar.xz && tar xfv llvm.tar.xz
RUN wget http://releases.llvm.org/9.0.0/compiler-rt-9.0.0.src.tar.xz -O compiler-rt.tar.xz && ls -lah && tar xfv compiler-rt.tar.xz

RUN mkdir /home/coll/fuzzer-test-suite_seeds/
COPY --chown=coll:coll misc/system/fuzzer-test-suite_seeds/ /home/coll/fuzzer-test-suite_seeds/
RUN mkdir /home/coll/fuzzer-test-suite/build/
COPY --chown=coll:coll misc/system/fuzzer-test-suite_afl_instrumented/ /home/coll/fuzzer-test-suite/build/

USER root
RUN apt-get update && apt-get install -y cmake rsync clang-6.0 build-essential software-properties-common 
RUN update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-3.8 100 && \
update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-6.0 1000 && \
update-alternatives --install /usr/bin/clang clang /usr/bin/clang-3.8 100  && \
update-alternatives --install /usr/bin/clang clang /usr/bin/clang-3.8 100 && \
update-alternatives --install /usr/bin/clang clang /usr/bin/clang-6.0 1000 
USER coll