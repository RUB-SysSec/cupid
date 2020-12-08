FROM fuzzer-system

USER coll

# install AFL
RUN wget http://lcamtuf.coredump.cx/afl/releases/afl-2.52b.tgz && tar xfv afl-2.52b.tgz && cd afl-2.52b && make -j && ls && ./afl-clang --version

# build LAVA-M
RUN cd ~; cd lava_corpus/LAVA-M/base64/coreutils-8.24-lava-safe/ && ./configure CC=/home/coll/afl-2.52b/afl-gcc CXX=/home/coll/afl-2.52b/afl-g++ && make -j
RUN cd ~; cd lava_corpus/LAVA-M/md5sum/coreutils-8.24-lava-safe/ && ./configure CC=/home/coll/afl-2.52b/afl-gcc CXX=/home/coll/afl-2.52b/afl-g++ && make -j
RUN cd ~; cd lava_corpus/LAVA-M/uniq/coreutils-8.24-lava-safe/ && ./configure CC=/home/coll/afl-2.52b/afl-gcc CXX=/home/coll/afl-2.52b/afl-g++ && make -j
RUN cd ~; cd lava_corpus/LAVA-M/who/coreutils-8.24-lava-safe/ && ./configure CC=/home/coll/afl-2.52b/afl-gcc CXX=/home/coll/afl-2.52b/afl-g++ && make -j