FROM fuzzer-system

USER coll

# install AFL
RUN git clone https://github.com/mboehme/aflfast.git && cd aflfast && git checkout 4e672d6e92 && make -j && ls && ./afl-clang --version

# build LAVA-M
RUN cd ~; cd lava_corpus/LAVA-M/base64/coreutils-8.24-lava-safe/ && ./configure CC=/home/coll/aflfast/afl-gcc CXX=/home/coll/aflfast/afl-g++ && make -j
RUN cd ~; cd lava_corpus/LAVA-M/md5sum/coreutils-8.24-lava-safe/ && ./configure CC=/home/coll/aflfast/afl-gcc CXX=/home/coll/aflfast/afl-g++ && make -j
RUN cd ~; cd lava_corpus/LAVA-M/uniq/coreutils-8.24-lava-safe/ && ./configure CC=/home/coll/aflfast/afl-gcc CXX=/home/coll/aflfast/afl-g++ && make -j
RUN cd ~; cd lava_corpus/LAVA-M/who/coreutils-8.24-lava-safe/ && ./configure CC=/home/coll/aflfast/afl-gcc CXX=/home/coll/aflfast/afl-g++ && make -j