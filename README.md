# Cupid: Automatic Fuzzer Selection for Collaborative Fuzzing

Get the paper [here](https://www.ei.ruhr-uni-bochum.de/media/emma/veroeffentlichungen/2020/09/26/ACSAC20-Cupid_TiM9H07.pdf).

Citation:

```
@article{cupid,
  title={Cupid: Automatic Fuzzer Selection for Collaborative Fuzzing},
  author={G{\"u}ler, Emre and G{\"o}rz, Philipp and Geretto, Elia and Jemmett, Andrea and {\"O}sterlund, Sebastian and Bos, Herbert and Giuffrida, Cristiano and Holz, Thorsten}
  booktitle = {Annual Computer Security Applications Conference (ACSAC)},
  doi = {10.1145/3427228.3427266},
  year = {2020}
}
```

# About

The idea behind Cupid is to automatically collect data on how well different fuzzers perform on a diverse set of binaries and use this data to predict which combination of fuzzers will perform well when executed in collaboration (i.e. in parallel - also called ensemble fuzzing). 

In previous research, [EnFuzz](https://www.usenix.org/system/files/sec19-chen-yuanliang.pdfhttps://www.usenix.org/system/files/sec19-chen-yuanliang.pdf) has shown that, in collaborative fuzzing scenarios, there is a difference in performance between choosing multiple instances of the same fuzzer and using a *diverse* set of fuzzers. We expand on this idea by avoiding the human expert guidance that was necessary to select the fuzzers and instead we use an automatic, data-driven approach.

In Cupid, we basically:

* Build docker images for every fuzzer (e.g. AFL, FairFuzz, Honggfuzz, etc.)

* Let all of them run in isolation (i.e. not in parallel) on a set of binaries, for a limited time period

* Use different seeds to explore more of the program space of every binary

* As randomness is an inherent property of fuzzing, we need to do the above step many times (e.g. 30 runs for every fuzzer+binary+seed combination) 

* Collect data on which branches the fuzzers were able to solve and how often

* Use our *complementarity* metric as outlined in the paper to calculate which fuzzers would profit from working with any of the other fuzzers in a collaborative run, i.e., how well a combination of fuzzers would complement each other

* Make a prediction on which combination of fuzzers should be used in future collaborative runs on any binary - where the quality of the prediction depends on the quality of the training data and how representative the binaries are of unknown real-world binaries

Per default, Cupid comes with these fuzzers: 

* [AFL](https://github.com/google/AFL)

* [AFLFast](https://github.com/mboehme/aflfast)

* [FairFuzz](https://github.com/carolemieux/afl-rb)

* [Honggfuzz](https://github.com/google/honggfuzz)

* lafintel<sup>1</sup>

* [LibFuzzer](https://llvm.org/docs/LibFuzzer.html)

* [QSYM]([https://github.com/sslab-gatech/qsym)

* [Radamsa](https://gitlab.com/akihe/radamsa)

¹It's not really lafintel, as Google's fuzzer-test-suite did not build with the LLVM passes, so it's just an old [AFL++](https://github.com/AFLplusplus/AFLplusplus) version with compcov instead.

For specific version numbers, please refer to our paper.

We have forked and extended [LibFuzzer](https://github.com/phi-go/llvm-project/tree/fuzzer_sync) and [Honggfuzz](https://github.com/phi-go/honggfuzz/tree/2.0_w_sync) to support AFL-style exchange of corpus seeds. To our understanding, this is the first cross-fuzzer implementation of corpus synchronisation between afl-based fuzzers and LibFuzzer/Honggfuzz in both directions.

# Usage

**Attention:** Please note that in some rare occasions, Cupid has to harshly terminate some fuzzers, delete their directories and forcefully remove files, so please only use Cupid on a machine where no important data can be lost (i.e. a test machine or a virtual machine).

As Cupid needs to build docker images for all fuzzers and let each of them build their own binaries (to avoid problems with different instrumentation methods), building all images can take up to 100GB of disk space. There is room for improvement here, e.g., some of the fuzzers could share the same binaries etc. But as of yet, no such fix is planned, so this is the only way to build the images right now. But you can jump to our artifact evaluation section below to find out how to remove some of the fuzzers and binaries if you don't have enough space.

## Install

You need Python 3 (we've tested the code with v3.6.9, you should have at least the same version because we use some Python futures that are unavailable in older versions). And you need to install screen (Ubuntu 18.04 example):

```
sudo apt install python3 screen
```

We have to install some Python packages:

```
python3 -m pip install python-ptrace oslo_concurrency
```

And then we need to build and install a custom Python package that is used to quickly track branch coverage:

```shell
$ git clone git@github.com:egueler/quickcov.git
$ cd quickcov
$ ./build.sh
# check if it worked:
$ python3 -c "import quickcov"
```

Now go back to Cupid.

In the first step, build all the necessary images by calling:

```shell
$ ./docker/build.sh
```

The script should abort in case of error. 

## Run

If everythings works fine, you can start the fuzzing process by calling `control.py`:

```
$ python3 control.py --timeout 60 --fuzzers afl,libfuzzer --binary base64
```

Which starts two fuzzers in parallel (`AFL` and `LibFuzzer`) and let's them fuzz LAVA-M's `base64` for sixty seconds. Note that the fuzzing output directory is set to `/dev/shm/sync{random_name}` so make sure that you have enough memory for longer runs. When the run is done, it dumps a pickle file containing all relevant information (mode, binary, plot information, branch coverage, etc.). If you want the output directory to be removed automatically (i.e. you don't want to keep the corpus), you can set `CLEANUP=1` as an environment variable before running `control.py`.

Explanation for the parameters:

`--fuzzers` can be either a comma-separated list of fuzzers (allowed values are `qsym, afl, aflfast, fairfuzz, libfuzzer, honggfuzz, radamsa, lafintel`) which we call the custom-mode, or any of our other modes: `enfuzz, enfuzz-q, cupid`, which pre-selects the four fuzzers described in the paper.

`--binary` can be any of these values: `base64, md5sum, who, uniq, boringssl, c-ares, freetype2, guetzli, harfbuzz, json, lcms, libarchive, libjpeg-turbo, libpng, libssh, libxml2, llvm-libcxxabi, openssl-1.0.1f, openssl-1.0.2d, openssl-1.1.0c, openthread, pcre2, proj4, re2, sqlite, vorbis, woff2, wpantund`, where the first four binaries are from LAVA-M (`base64, md5sum, who, uniq`) and the rest is from [Google's fuzzer-test-suite](https://github.com/google/fuzzer-test-suite).

Now find out what the pickle file is called via `ls` and execute this to generate a branch coverage plot:

```shell
$ python3 plot.py [name].pickle
```

If you needed to abort one of the `control.py` runs, you probably aborted the cleanup stage. To cleanup all docker containers that might be still fuzzing in the background, run:

```
$ python3 stop.py
```



# Artifact Evaluation

Please refer to our [artifact evaluation page here](https://github.com/egueler/cupid-artifact-eval) for more information.
