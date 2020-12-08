#!/usr/bin/python3

from __future__ import print_function

import os

fuzzers = ["qsym", "afl", "aflfast", "fairfuzz", "libfuzzer", "honggfuzz", "radamsa"] 
# lafintel is excluded because it uses plain binaries in QEMU mode

fuzzerToSrc = {
               "afl": "/home/coll/afl-2.52b/", 
               "aflfast": "/home/coll/aflfast/", 
               "fairfuzz": "/home/coll/afl-rb/", 
               "honggfuzz": "/home/coll/honggfuzz/", 
               "radamsa": "/home/coll/AFLplusplus/",
               "qsym": "/home/coll/afl-2.52b/",
               "libfuzzer": ""
}

targets = [
  "boringssl-2016-02-12",
  "c-ares-CVE-2016-5180",
  "freetype2-2017",
  "guetzli-2017-3-30",
  "harfbuzz-1.3.2",
  "json-2017-02-12",
  "lcms-2017-03-21",
  "libarchive-2017-01-04",
  "libjpeg-turbo-07-2017",
  "libpng-1.2.56",
  "libssh-2017-1272",
  "libxml2-v2.9.2",
  "llvm-libcxxabi-2017-01-27",
  "openssl-1.0.1f",
  "openssl-1.0.2d",
  "openssl-1.1.0c",
  "openthread-2018-02-27",
  "pcre2-10.00",
  "proj4-2017-08-14",
  "re2-2014-12-09",
  "sqlite-2016-11-14",
  "vorbis-2017-12-11",
  "woff2-2016-05-06",
  "wpantund-2018-02-27"
]

for fuzzer in fuzzers:
  src = fuzzerToSrc[fuzzer]

  aflENV = "LIBFUZZER_SRC=/home/coll/compiler-rt-9.0.0.src/lib/fuzzer/ \
  AFL_SRC={src} FUZZING_ENGINE=afl"
  libfuzzerENV = "LIBFUZZER_SRC=/home/coll/build_clang/llvm-project/compiler-rt/lib/fuzzer/"
  honggfuzzENV = "LIBFUZZER_SRC=/home/coll/compiler-rt-9.0.0.src/lib/fuzzer/ \
  HONGGFUZZ_SRC={src} FUZZING_ENGINE=honggfuzz"
  qsymENV = "CC=clang CXX=clang++ LIBFUZZER_SRC=/home/coll/compiler-rt-9.0.0.src/lib/fuzzer/ \
  AFL_SRC={src} FUZZING_ENGINE=coverage"
  plain = ""
  cp_plain = ""

  if fuzzer == "libfuzzer":
    env = libfuzzerENV
  elif fuzzer == "honggfuzz":
    env = honggfuzzENV.format(src=src)
  elif fuzzer == "qsym":
    plain = "-plain"
    cp_plain = f"cp -r /home/coll/fuzzer-test-suite /home/coll/fuzzer-test-suite{plain};"
    env = qsymENV.format(src=src)
  else:
    env = aflENV.format(src=src)

  targetCommand = 'docker exec --user coll -t fuzzer-{fuzzer}-build bash -ic \
  "{cp_plain} mkdir /home/coll/fuzzer-test-suite{plain}/build; \
  cd /home/coll/fuzzer-test-suite{plain}/build; \
  rm -rf RUNDIR-{target}; \
  {env} /home/coll/fuzzer-test-suite{plain}/build.sh {target}"; '

  targetCommands = []
  for target in targets:
    targetCommands.append(targetCommand.format(fuzzer=fuzzer, src=src, target=target, env=env, plain=plain, cp_plain=cp_plain))
  targetCommands = "\n".join(targetCommands)

  os_str = \
  """
  docker stop fuzzer-{fuzzer}-build; docker rm fuzzer-{fuzzer}-build;
  docker run -u {user_id}:{group_id} --ipc="host" --cap-add=SYS_PTRACE --security-opt seccomp=unconfined --name=fuzzer-{fuzzer}-build -td fuzzer-{fuzzer};
  {targetCommands}
  docker commit fuzzer-{fuzzer}-build fuzzer-{fuzzer};
  """.format(fuzzer=fuzzer, targetCommands=targetCommands, user_id=os.getuid(), group_id=os.getgid())
  
  print(os_str)
  os.system(os_str)
