FROM fuzzer-system

USER coll

# install Radamsa
#RUN git clone https://gitlab.com/akihe/radamsa.git && cd radamsa && git checkout 02311625 && make

# install AFL++ with radamsa support
RUN git clone https://github.com/vanhauser-thc/AFLplusplus.git && cd AFLplusplus && git checkout 553d9f5cfc6a9adc1a0a89bab477cb02ff174e58
# fix afl++ bug (config.h not found)
RUN cd AFLplusplus && sed -ie 's/#include "config.h"/#include "..\/config.h"/g' llvm_mode/afl-llvm-rt.o.c && sed -ie 's/#include "types.h"/#include "..\/types.h"/g' llvm_mode/afl-llvm-rt.o.c 
RUN cd AFLplusplus && make -j && make radamsa && cd llvm_mode && make -j

# build LAVA-M
RUN cd ~; cd lava_corpus/LAVA-M/base64/coreutils-8.24-lava-safe/ && ./configure CC=/home/coll/AFLplusplus/afl-gcc CXX=/home/coll/AFLplusplus/afl-g++ && make -j
RUN cd ~; cd lava_corpus/LAVA-M/md5sum/coreutils-8.24-lava-safe/ && ./configure CC=/home/coll/AFLplusplus/afl-gcc CXX=/home/coll/AFLplusplus/afl-g++ && make -j
RUN cd ~; cd lava_corpus/LAVA-M/uniq/coreutils-8.24-lava-safe/ && ./configure CC=/home/coll/AFLplusplus/afl-gcc CXX=/home/coll/AFLplusplus/afl-g++ && make -j
RUN cd ~; cd lava_corpus/LAVA-M/who/coreutils-8.24-lava-safe/ && ./configure CC=/home/coll/AFLplusplus/afl-gcc CXX=/home/coll/AFLplusplus/afl-g++ && make -j
