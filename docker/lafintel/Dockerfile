FROM fuzzer-system

USER root

RUN apt-get install -y libcapstone-dev libpixman-1-dev

USER coll

# install AFL++ with laf-intel support
RUN git clone https://github.com/vanhauser-thc/AFLplusplus.git && cd AFLplusplus && git checkout 553d9f5cfc6a9adc1a0a89bab477cb02ff174e58
# fix afl++ bug (config.h not found)
RUN cd AFLplusplus && sed -ie 's/#include "config.h"/#include "..\/config.h"/g' llvm_mode/afl-llvm-rt.o.c && sed -ie 's/#include "types.h"/#include "..\/types.h"/g' llvm_mode/afl-llvm-rt.o.c 
RUN cd AFLplusplus && make -j && cd llvm_mode && make -j && cd ../qemu_mode && ./build_qemu_support.sh
USER root
RUN cd /home/coll/AFLplusplus/ && make install 
USER coll

RUN mkdir uninstrumented

ARG CC=
ARG CXX=

# build uninstrumented LAVA-M
RUN tar xfv lava_corpus.tar.xz -C uninstrumented
RUN cd ~; cd uninstrumented/lava_corpus/LAVA-M/base64/coreutils-8.24-lava-safe/ && ./configure && make -j
RUN cd ~; cd uninstrumented/lava_corpus/LAVA-M/md5sum/coreutils-8.24-lava-safe/ && ./configure && make -j
RUN cd ~; cd uninstrumented/lava_corpus/LAVA-M/uniq/coreutils-8.24-lava-safe/   && ./configure && make -j
RUN cd ~; cd uninstrumented/lava_corpus/LAVA-M/who/coreutils-8.24-lava-safe/    && ./configure && make -j

# copy uninstrumented fuzzer-test-suite
RUN mkdir -p /home/coll/uninstrumented/fuzzer-test-suite
COPY --chown=coll:coll misc/data/fuzzer-test-suite_uninstrumented/* /home/coll/uninstrumented/fuzzer-test-suite/

ARG AFL_COMPCOV_LEVEL=2