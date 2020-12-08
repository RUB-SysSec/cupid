#!/usr/bin/python

import time, os, sys, random, json, argparse, copy, pickle, datetime
import signal, threading, subprocess, datetime
from enum import Enum
import quickcov
from threading import Lock
from config import *
from misc import *
from stop import *
from FuzzerManager import *
from Fuzzer import *
from multiprocessing import Pipe
try:
    from reprlib import repr
except ImportError:
    pass

INOTIFY_SLEEP = 1
excluded_fuzzers = [] # exclude some fuzzers because they're not ready yet
available_fuzzers = list(set(fuzzers) - set(excluded_fuzzers))

def file_watch_thread():
  global timestamps, timestamps_lock
  # set directory watch thread to last available core
  os.system("taskset -c -p %d %d" % (random.choice(list(CoreManager().core.values())), os.getpid()))
  sync_requested = False
  while not terminate_me:
    with timestamps_lock:
      timestamps.update(check_for_new_files(get_sync_dir(), timestamps))
    if sync_requested:
      print("force sync request fulfilled")
      inotify_parent.send(1)
      sync_requested = False
    i = 0
    while i < INOTIFY_SLEEP and not terminate_me:
      i += 1
      time.sleep(1)
      if inotify_parent.poll():
        print("force syn request received")
        inotify_parent.recv()
        sync_requested = True
        break
  inotify_parent.close()
  inotify_child.close()
  print("file_watch_thread finished.")

def force_sync_scan():
  inotify_child.send(1)
  inotify_child.recv()
  
parser = argparse.ArgumentParser(description="", prog="control.py")
parser.add_argument('--timeout', '-t', dest="timeout", help="Timeout", nargs=1, required=True)
parser.add_argument('--fuzzers', '-f', dest="fuzzers", help="Comma-separated list of fuzzers (e.g. 'afl,libfuzzer') or name for pre-compiled list of fuzzers (enfuzz, enfuzz-q, cupid)", nargs=1, required=True)
parser.add_argument('--binary', '-b', dest="binary", help="Name of binary (e.g. base64)", nargs=1, required=True)
parser.add_argument('--seed', dest="seed", help="Select seed (1-5), don't set this to use default seed")
args = parser.parse_args()

# check if AFL can run
if not check_afl():
  print("AFL is not configured, please execute: ")
  print("sudo bash -c 'echo core >/proc/sys/kernel/core_pattern; cd /sys/devices/system/cpu; echo performance | tee cpu*/cpufreq/scaling_governor'")
  kill_all_fuzzers(get_sync_id())
  sys.exit(-1)

# cleanup first
kill_all_fuzzers(get_sync_id())
delete_shm_sync(get_sync_id())

# check if there are any remaining screen sessions that would fuck up our own sessions
if int(get_shell("docker container ls | grep eval | wc -l")) > 0:
  print("There are already some eval docker sessions running (check `docker container ls`)")
  print("I can't run under these circumstances.")
  sys.exit(-1)

timestamps = {}
timestamps_lock = Lock()
terminate_me = False
input_file = None
inotify_parent, inotify_child = Pipe()

if args.timeout:
  timeout = int(args.timeout[0])
if args.binary:
  binary = args.binary[0]
if args.seed:
  input_file = args.seed[0]
if args.fuzzers:
  if "," in args.fuzzers[0] or args.fuzzers[0] in fuzzers:
    start_fuzzers = args.fuzzers[0].split(",")
    mode_str = "custom (%s)" % args.fuzzers[0]
    for f in start_fuzzers:
      if f not in fuzzers:
        print("Unknown fuzzer %s" % f)
        sys.exit(-1)
  else:
    mode_str = args.fuzzers[0]
    mode_to_start_fuzzers = {
      "enfuzz": ENFUZZ_START_FUZZERS,
      "enfuzz-q": ENFUZZ_Q_START_FUZZERS,
      "cupid": CUPID_START_FUZZERS
    }
    print(f"started in {mode_str} mode")
    if mode_str in mode_to_start_fuzzers:
      start_fuzzers = mode_to_start_fuzzers[mode_str]
    else:
      print("unknown mode %s" % args.fuzzers[0])
      sys.exit(-1)

# reserve some cores for this run
CoreManager(len(start_fuzzers)) # initialize CoreManager
print("Running in %s mode" % mode_str)
print("Using fuzzers: %s" % start_fuzzers)

start_time = get_unix_timestamp()
last_hit = 0

# start the fuzzers
fm = FuzzerManager(binary, input_file, timestamps, timestamps_lock)
(toolset, project) = binaryToToolsetAndProject[binary]
random.shuffle(start_fuzzers)
fuzzer_objs = []
for core,fuzzer in enumerate(start_fuzzers):
  fo = fm.create_fuzzer(fuzzer)
  fo.set_core(core)
  fm.add(fo)
  fuzzer_objs.append(fo)
print("fuzzer_objs: %s" % fuzzer_objs)
start_time = get_unix_timestamp()
fm.start()

t = threading.Thread(target=file_watch_thread)
t.start()

time.sleep(timeout)

# runtime is over
# stop FuzzerManager and all fuzzers
print("Stopping all fuzzers")
fm.stop()
force_sync_scan()

# output stats and coverage info
print("Getting plots")
info = {}
(plot, bitmap, final_coverage) = fm.get_total_coverage()
plot_filename = "plot-%s.pickle" % get_sync_id()
print("Dumping %s" % plot_filename)
info["plot"] = plot
info["info"] = {"timeout": timeout, "fuzzers": start_fuzzers, "binary": binary}
f = open(plot_filename, "wb+")
pickle.dump(info, f)
f.close()

# dump timestamps
with timestamps_lock:
  timestamps_filename = "timestamps-%s.pickle" % get_sync_id()
  f = open(timestamps_filename, "wb+")
  pickle.dump(timestamps, f)
  f.close()

# cleanup fuzzermanager/quickcov
fm.cleanup()
# free the cores we have been using
CoreManager().cleanup()
# stop thread
terminate_me = True
# make sure the fuzzers are really killed
kill_all_fuzzers(get_sync_id())
# if CLEANUP environment variable is given, delete the fuzzer output directory too
if os.getenv('CLEANUP') is not None:
  delete_shm_sync(get_sync_id())

print("Finished.")