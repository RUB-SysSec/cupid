#!/usr/bin/python

from enum import Enum

binaryToToolsetAndProject = {
  "boringssl": ("google-test-suite", "boringssl-2016-02-12"),
  "c-ares": ("google-test-suite", "c-ares-CVE-2016-5180"),
  "freetype2": ("google-test-suite", "freetype2-2017"),
  "guetzli": ("google-test-suite", "guetzli-2017-3-30"),
  "harfbuzz": ("google-test-suite", "harfbuzz-1.3.2"),
  "json": ("google-test-suite", "json-2017-02-12"),
  "lcms": ("google-test-suite", "lcms-2017-03-21"),
  "libarchive": ("google-test-suite", "libarchive-2017-01-04"),
  "libjpeg-turbo": ("google-test-suite", "libjpeg-turbo-07-2017"),
  "libpng": ("google-test-suite", "libpng-1.2.56"),
  "libssh": ("google-test-suite", "libssh-2017-1272"),
  "libxml2": ("google-test-suite", "libxml2-v2.9.2"),
  "llvm-libcxxabi": ("google-test-suite", "llvm-libcxxabi-2017-01-27"),
  "openssl-1.0.1f": ("google-test-suite", "openssl-1.0.1f"),
  "openssl-1.0.2d": ("google-test-suite", "openssl-1.0.2d"),
  "openssl-1.1.0c": ("google-test-suite", "openssl-1.1.0c"),
  "openthread": ("google-test-suite", "openthread-2018-02-27"),
  "pcre2": ("google-test-suite", "pcre2-10.00"),
  "proj4": ("google-test-suite", "proj4-2017-08-14"),
  "re2": ("google-test-suite", "re2-2014-12-09"),
  "sqlite": ("google-test-suite", "sqlite-2016-11-14"),
  "vorbis": ("google-test-suite", "vorbis-2017-12-11"),
  "woff2": ("google-test-suite", "woff2-2016-05-06"),
  "wpantund": ("google-test-suite", "wpantund-2018-02-27"),
  "base64": ("LAVA-M", "base64"),
  "md5sum": ("LAVA-M", "md5sum"),
  "uniq": ("LAVA-M", "uniq"),
  "who": ("LAVA-M", "who")
}

supportsLibfuzzer = {
  "google-test-suite": True,
  "LAVA-M": False,
}

fuzzers = ["afl", "aflfast", "fairfuzz", "qsym", "radamsa", "libfuzzer", "honggfuzz", "lafintel"]

fuzzerType = {"afl": "afl",
              "aflfast": "afl",
              "fairfuzz": "afl",
              "qsym": "afl",
              "radamsa": "afl",
              "lafintel": "afl",
              "honggfuzz": "honggfuzz",
              "libfuzzer": "libfuzzer"}

binaryTails = {
  "openssl-1.1.0c": "-bignum",
  "openthread": "-ip6"
}

toolsetPaths = {
  "google-test-suite": "/home/coll/fuzzer-test-suite/build/RUNDIR-{full_binary}/{full_binary}-afl{tail}",
  "LAVA-M": "/home/coll/lava_corpus/LAVA-M/{binary}/coreutils-8.24-lava-safe/src/{binary}"
}

toolsetPathsUninstrumented = {
  "LAVA-M": "/home/coll/uninstrumented/lava_corpus/LAVA-M/{binary}/coreutils-8.24-lava-safe/src/{binary}",
  "google-test-suite": "/home/coll/fuzzer-test-suite-plain/build/RUNDIR-{full_binary}/{full_binary}-coverage"
}

toolsetPathsUninstrumentedLafintel = {
  "google-test-suite": "/home/coll/uninstrumented/fuzzer-test-suite/{full_binary}-plain"
}

toolsetPathsLibfuzzer = {
  "google-test-suite": "/home/coll/fuzzer-test-suite/build/RUNDIR-{full_binary}/{full_binary}-fsanitize_fuzzer{tail}",
  "LAVA-M": "/home/coll/lava_corpus/LAVA-M/{binary}/coreutils-8.24-lava-safe/fuzz"
}

toolsetPathsHonggfuzz = {
  "google-test-suite": "/home/coll/fuzzer-test-suite/build/RUNDIR-{full_binary}/{full_binary}-honggfuzz{tail}",
  "LAVA-M": "/home/coll/lava_corpus/LAVA-M/{binary}/coreutils-8.24-lava-safe/src/{binary}"
}

QUICKCOV_PATH = "quickcov_instrumented"

AFL_DIRECTORIES = {
  "afl": "/home/coll/afl-2.52b/",
  "aflfast": "/home/coll/aflfast/",
  "fairfuzz": "/home/coll/afl-rb/",
  "qsym": "/home/coll/afl-2.52b/",
  "lafintel": "/home/coll/AFLplusplus/",
  "radamsa": "/home/coll/AFLplusplus/"
}

binaryToInputDirectory = {
  "base64": "/home/coll/lava_corpus/LAVA-M/base64/fuzzer_input",
  "md5sum": "/home/coll/lava_corpus/LAVA-M/md5sum/fuzzer_input",
  "who":    "/home/coll/lava_corpus/LAVA-M/who/fuzzer_input",
  "uniq":   "/home/coll/lava_corpus/LAVA-M/uniq/fuzzer_input",
  "boringssl": "/home/coll/fuzzer-test-suite_seeds/RUNDIR-boringssl-2016-02-12/seeds/",
  "freetype2": "/home/coll/fuzzer-test-suite_seeds/RUNDIR-freetype2-2017/seeds/",
  "guetzli": "/home/coll/fuzzer-test-suite_seeds/RUNDIR-guetzli-2017-3-30/seeds/",
  "harfbuzz": "/home/coll/fuzzer-test-suite_seeds/RUNDIR-harfbuzz-1.3.2/seeds/",
  "json": "/home/coll/fuzzer-test-suite_seeds/RUNDIR-json-2017-02-12/seeds/",
  "lcms": "/home/coll/fuzzer-test-suite_seeds/RUNDIR-lcms-2017-03-21/seeds/",
  "libarchive": "/home/coll/fuzzer-test-suite_seeds/RUNDIR-libarchive-2017-01-04/seeds/",
  "libjpeg-turbo": "/home/coll/fuzzer-test-suite_seeds/RUNDIR-libjpeg-turbo-07-2017/seeds/",
  "libpng": "/home/coll/fuzzer-test-suite_seeds/RUNDIR-libpng-1.2.56/seeds/",
  "openthread": "/home/coll/fuzzer-test-suite_seeds/RUNDIR-openthread-2018-02-27/seeds/",
  "proj4": "/home/coll/fuzzer-test-suite_seeds/RUNDIR-proj4-2017-08-14/seeds/",
  "vorbis": "/home/coll/fuzzer-test-suite_seeds/RUNDIR-vorbis-2017-12-11/seeds/",
  "woff2": "/home/coll/fuzzer-test-suite_seeds/RUNDIR-woff2-2016-05-06/seeds/",
  "wpantund": "/home/coll/fuzzer-test-suite_seeds/RUNDIR-wpantund-2018-02-27/seeds/"
}

binaryToArguments = {
  "xml": "",
  "gnuplot": "",
  "boringssl": "",
  "c-ares": "",
  "freetype2": "",
  "guetzli": "",
  "harfbuzz": "",
  "json": "",
  "lcms": "",
  "libarchive": "",
  "libjpeg-turbo": "",
  "libpng": "",
  "libssh": "",
  "libxml2": "",
  "llvm-libcxxabi": "",
  "openssl-1.0.1f": "",
  "openssl-1.0.2d": "",
  "openssl-1.1.0c": "",
  "openthread": "",
  "pcre2": "",
  "proj4": "",
  "re2": "",
  "sqlite": "",
  "vorbis": "",
  "woff2": "",
  "wpantund": "",
  "base64": "-d",
  "md5sum": "-c",
  "uniq": "",
  "who": ""
}

ENFUZZ_Q_START_FUZZERS = ["afl", "aflfast", "fairfuzz", "qsym"]
ENFUZZ_START_FUZZERS = ["afl", "aflfast", "libfuzzer", "radamsa"]
CUPID_START_FUZZERS = ["fairfuzz", "qsym", "libfuzzer", "afl"]