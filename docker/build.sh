#!/bin/bash

set -x # activate debugging from here

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"

echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope

cd $SCRIPTPATH

# general system setup
docker build --tag=fuzzer-system -f $SCRIPTPATH/misc/system/Dockerfile $SCRIPTPATH

# qsym base
QSYM_BASE_PATH="$SCRIPTPATH/qsym-base"
if [ -d "$QSYM_BASE_PATH" ]; then
	(cd $QSYM_BASE_PATH; git checkout aabec86ea77;)
else
	(git clone https://github.com/sslab-gatech/qsym.git $SCRIPTPATH/qsym-base; $QSYM_BASE_PATH \
    && cd $SCRIPTPATH/qsym-base && git checkout aabec86ea77)
fi
(
	cd $SCRIPTPATH/qsym-base; \
	cp $SCRIPTPATH/qsym/qsym-base-docker $SCRIPTPATH/qsym-base/Dockerfile && \
	cp $SCRIPTPATH/minimizer-path.patch $SCRIPTPATH/qsym-base/minimizer-path.patch && \
	(patch -N -p1 < minimizer-path.patch || true)
)
docker build --tag=qsym-base $SCRIPTPATH/qsym-base/
# qsym
docker build --tag=fuzzer-qsym -f $SCRIPTPATH/qsym/Dockerfile $SCRIPTPATH
# afl
docker build --tag=fuzzer-afl -f $SCRIPTPATH/afl/Dockerfile $SCRIPTPATH
# aflfast
docker build --tag=fuzzer-aflfast -f $SCRIPTPATH/aflfast/Dockerfile $SCRIPTPATH
# fairfuzz / afl-rb
docker build --tag=fuzzer-fairfuzz -f $SCRIPTPATH/fairfuzz/Dockerfile $SCRIPTPATH
# lafintel
docker build --tag=fuzzer-lafintel -f $SCRIPTPATH/lafintel/Dockerfile $SCRIPTPATH
# honggfuzz
docker build --tag=fuzzer-honggfuzz -f $SCRIPTPATH/honggfuzz/Dockerfile $SCRIPTPATH
# qsym
docker build --tag=fuzzer-qsym -f $SCRIPTPATH/qsym/Dockerfile $SCRIPTPATH
# radamsa
docker build --tag=fuzzer-radamsa -f $SCRIPTPATH/radamsa/Dockerfile $SCRIPTPATH
# libfuzzer
docker build --tag=fuzzer-libfuzzer -f $SCRIPTPATH/libfuzzer/Dockerfile $SCRIPTPATH

# some packages from fuzzer-test-suite need ptrace functionality which 
# can not be enabled during docker build so we have to run that code in 
# privileged mode and save the changes
$SCRIPTPATH/build_test_suite.py

cd -

set +x # stop debugging from here
