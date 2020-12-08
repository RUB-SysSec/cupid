FROM fuzzer-system

USER coll

# install AFL
RUN git clone https://github.com/carolemieux/afl-rb.git && cd afl-rb && git checkout e529c1f1b366 && make -j && ls && ./afl-clang --version

# build LAVA-M
RUN cd ~; cd lava_corpus/LAVA-M/base64/coreutils-8.24-lava-safe/ && ./configure CC=/home/coll/afl-rb/afl-gcc CXX=/home/coll/afl-rb/afl-g++ && make -j
RUN cd ~; cd lava_corpus/LAVA-M/md5sum/coreutils-8.24-lava-safe/ && ./configure CC=/home/coll/afl-rb/afl-gcc CXX=/home/coll/afl-rb/afl-g++ && make -j
RUN cd ~; cd lava_corpus/LAVA-M/uniq/coreutils-8.24-lava-safe/ && ./configure CC=/home/coll/afl-rb/afl-gcc CXX=/home/coll/afl-rb/afl-g++ && make -j
RUN cd ~; cd lava_corpus/LAVA-M/who/coreutils-8.24-lava-safe/ && ./configure CC=/home/coll/afl-rb/afl-gcc CXX=/home/coll/afl-rb/afl-g++ && make -j