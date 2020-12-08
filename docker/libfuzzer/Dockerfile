FROM debian:stable as builder

RUN apt-get -y update && apt-get -y install cmake ninja-build g++ python3 python3-distutils git

# build llvm with sync support (and proper timeout in fork mode)
WORKDIR /build_clang/
RUN git clone --depth=1 --single-branch --branch fuzzer_sync https://github.com/phi-go/llvm-project.git &&\
    cd llvm-project && mkdir build && cd build &&\
    cmake -G Ninja -DLLVM_TARGETS_TO_BUILD=Native -DCMAKE_BUILD_TYPE=Release \
          -DLLVM_ENABLE_PROJECTS='clang;compiler-rt' -DCMAKE_INSTALL_PREFIX=/build_clang/install/ ../llvm &&\
    ninja && ninja install

FROM fuzzer-system

USER root
RUN apt-get update && \
    apt-get install -y --no-install-recommends libstdc++-8-dev binutils && \
    rm -rf /var/lib/apt/lists/*
#Copy build results of stage 1 to /usr/local.
COPY --from=builder /build_clang/install/ /usr/local/
COPY --from=builder /build_clang/ /home/coll/build_clang/

USER coll

# build LAVA-M with libfuzzer support
COPY misc/libfuzzer/base64.c lava_corpus/LAVA-M/base64/coreutils-8.24-lava-safe/src/
COPY misc/libfuzzer/base64_fuzz.c lava_corpus/LAVA-M/base64/coreutils-8.24-lava-safe/
RUN cd ~; cd lava_corpus/LAVA-M/base64/coreutils-8.24-lava-safe/ && make distclean && CC=clang CFLAGS="-O2 -fPIC -fno-omit-frame-pointer -gline-tables-only -fsanitize=fuzzer-no-link -fsanitize-coverage=trace-cmp,trace-gep,trace-div" ./configure --disable-silent-rules && make -j && clang -shared -O0 -fPIC -fno-omit-frame-pointer -gline-tables-only -fsanitize=fuzzer-no-link -fsanitize-coverage=trace-cmp,trace-gep,trace-div -Wl,--as-needed -o src/base64.so src/base64.o src/libver.a lib/libcoreutils.a  lib/libcoreutils.a && clang -fsanitize=fuzzer -Isrc/ -L. -g base64_fuzz.c -o fuzz /home/coll/lava_corpus/LAVA-M/base64/coreutils-8.24-lava-safe/src/base64.so

COPY misc/libfuzzer/md5sum.c lava_corpus/LAVA-M/md5sum/coreutils-8.24-lava-safe/src/
COPY misc/libfuzzer/md5sum_fuzz.c lava_corpus/LAVA-M/md5sum/coreutils-8.24-lava-safe/
RUN cd ~; cd lava_corpus/LAVA-M/md5sum/coreutils-8.24-lava-safe/ && make distclean && CC=clang CFLAGS="-O2 -fPIC -fno-omit-frame-pointer -gline-tables-only -fsanitize=fuzzer-no-link -fsanitize-coverage=trace-cmp,trace-gep,trace-div" ./configure --disable-silent-rules && make -j && clang -shared -O0 -fPIC -fno-omit-frame-pointer -gline-tables-only -fsanitize=fuzzer-no-link -fsanitize-coverage=trace-cmp,trace-gep,trace-div -Wl,--as-needed -o src/md5sum.so src/src_md5sum-md5sum.o src/libver.a lib/libcoreutils.a lib/libcoreutils.a && clang -fsanitize=fuzzer -Isrc/ -L. -g md5sum_fuzz.c -o fuzz /home/coll/lava_corpus/LAVA-M/md5sum/coreutils-8.24-lava-safe/src/md5sum.so

COPY misc/libfuzzer/uniq.c lava_corpus/LAVA-M/uniq/coreutils-8.24-lava-safe/src/
COPY misc/libfuzzer/uniq_fuzz.c lava_corpus/LAVA-M/uniq/coreutils-8.24-lava-safe/
RUN cd ~; cd lava_corpus/LAVA-M/uniq/coreutils-8.24-lava-safe/ && CC=clang CFLAGS="-O2 -fPIC -fno-omit-frame-pointer -gline-tables-only -fsanitize=fuzzer-no-link -fsanitize-coverage=trace-cmp,trace-gep,trace-div" ./configure --disable-silent-rules && make -j && clang -shared -O0 -fPIC -fno-omit-frame-pointer -gline-tables-only -fsanitize=fuzzer-no-link -fsanitize-coverage=trace-cmp,trace-gep,trace-div -Wl,--as-needed -o src/uniq.so src/uniq.o src/libver.a lib/libcoreutils.a lib/libcoreutils.a && clang -fsanitize=fuzzer -Isrc/ -L. -g uniq_fuzz.c -o fuzz /home/coll/lava_corpus/LAVA-M/uniq/coreutils-8.24-lava-safe/src/uniq.so

COPY misc/libfuzzer/who.c lava_corpus/LAVA-M/who/coreutils-8.24-lava-safe/src/
COPY misc/libfuzzer/who_fuzz.c lava_corpus/LAVA-M/who/coreutils-8.24-lava-safe/
RUN cd ~; cd lava_corpus/LAVA-M/who/coreutils-8.24-lava-safe/ && CC=clang CFLAGS="-O2 -fPIC -fno-omit-frame-pointer -gline-tables-only -fsanitize=fuzzer-no-link -fsanitize-coverage=trace-cmp,trace-gep,trace-div" ./configure --disable-silent-rules && make -j && clang -shared -O0 -fPIC -fno-omit-frame-pointer -gline-tables-only -fsanitize=fuzzer-no-link -fsanitize-coverage=trace-cmp,trace-gep,trace-div -Wl,--as-needed  -o src/who.so src/who.o src/libver.a lib/libcoreutils.a  lib/libcoreutils.a && clang -fsanitize=fuzzer -Isrc/ -L. -g who_fuzz.c -o fuzz /home/coll/lava_corpus/LAVA-M/who/coreutils-8.24-lava-safe/src/who.so

COPY afl_wrapper.py .