FROM fuzzer-system

USER root

# install new clang version for fuzzer-test-suite later
RUN echo "deb http://apt.llvm.org/xenial/ llvm-toolchain-xenial-9 main" >> /etc/apt/sources.list
RUN echo "deb-src http://apt.llvm.org/xenial/ llvm-toolchain-xenial-9 main" >> /etc/apt/sources.list
RUN curl https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -
RUN curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add -
RUN apt-get update -y
RUN apt-get install -y clang-9
RUN rm /usr/bin/clang && rm /usr/bin/clang++
RUN ln -s /usr/bin/clang-9 /usr/bin/clang
RUN ln -s /usr/bin/clang++-9 /usr/bin/clang++

USER coll

# install Honggfuzz
RUN git clone --depth=1 --single-branch --branch 2.0_w_sync https://github.com/phi-go/honggfuzz.git && cd honggfuzz && make -j && ls && ./honggfuzz --help

# build LAVA-M
RUN cd ~; cd lava_corpus/LAVA-M/base64/coreutils-8.24-lava-safe/ && ./configure CC=/home/coll/honggfuzz/hfuzz_cc/hfuzz-clang CXX=/home/coll/honggfuzz/hfuzz_cc/hfuzz-clang++ && make -j
RUN cd ~; cd lava_corpus/LAVA-M/md5sum/coreutils-8.24-lava-safe/ && ./configure CC=/home/coll/honggfuzz/hfuzz_cc/hfuzz-clang CXX=/home/coll/honggfuzz/hfuzz_cc/hfuzz-clang++ && make -j
RUN cd ~; cd lava_corpus/LAVA-M/uniq/coreutils-8.24-lava-safe/ && ./configure CC=/home/coll/honggfuzz/hfuzz_cc/hfuzz-clang CXX=/home/coll/honggfuzz/hfuzz_cc/hfuzz-clang++ && make -j
RUN cd ~; cd lava_corpus/LAVA-M/who/coreutils-8.24-lava-safe/ && ./configure CC=/home/coll/honggfuzz/hfuzz_cc/hfuzz-clang CXX=/home/coll/honggfuzz/hfuzz_cc/hfuzz-clang++ && make -j

COPY afl_wrapper.py .