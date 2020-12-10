#!/usr/bin/python

import sys, os, signal, time, glob, fcntl, argparse, hashlib
from shutil import copyfile

terminateMe = False
mem = set() # afl cache
other_fuzzers_mem = set() # cache for sync of other fuzzers
counter = 0
other_fuzzer_counter = 0

def getQueueFiles(folder):
  files = []
  for d in os.listdir(folder):
    p = os.path.abspath(os.path.join(folder, d))
    if os.path.isdir(p):
      files.extend(getQueueFiles(p))
    else:
      basename = os.path.basename(p)
      files.append(p)
  return files

def sha1file(f):
  sha1sum = hashlib.sha1()
  with open(f, 'rb') as source:
    block = source.read(2**16)
    while len(block) != 0:
      sha1sum.update(block)
      block = source.read(2**16)
  return sha1sum.hexdigest()

def watcher(src, dest, fuzzer_dirs, sync_dir, sleep_time):
  global terminateMe, counter, mem, other_fuzzers_mem, other_fuzzer_counter

  dest_with_queue = os.path.join(dest, "queue")
  os.system("mkdir -p %s" % dest_with_queue)

  while not terminateMe:
    # scan dir for new output and copy it afl style
    queue = [f for f in getQueueFiles(src) if f not in mem]
    mem.update(queue)
    print "Found %d new files that need to be afl-style" % len(queue)
    for f in queue:
      mem.add(f)
      name = "id:{i},src:000000,op:wrp".format(i="%06d" % counter)
      currentDest = os.path.join(dest_with_queue, name)
      print "Copying file %s to %s" % (f, currentDest)
      try:
          copyfile(f, currentDest)
      except:
          print "Copying file failed." 
          return
      counter += 1
    # scan all other fuzzer sync dirs for new output and copy it to sync dir if necessary
    if sync_dir is not None and fuzzer_dirs is not None:
      print "Checking %s" % fuzzer_dirs
      for fuzzer_dir in fuzzer_dirs:
        if not os.path.isdir(fuzzer_dir):
          continue
        queue = [f for f in getQueueFiles(fuzzer_dir) if sha1file(f) not in other_fuzzers_mem and os.path.getsize(f) > 0]
        # remove duplicate hashes
        sha_queue = set([sha1file(f) for f in queue])
        unique_queue = set()
        for f in queue:
          s = sha1file(f)
          if s in sha_queue:
            unique_queue.add(f)
            sha_queue.remove(s)
        queue = unique_queue
        # go through queue of new files and add them to our sync dir
        if len(queue) > 0:
          other_fuzzers_mem.update([sha1file(f) for f in queue])
          print "Found %d new files from other fuzzer, copying..." % (len(queue))
          for f in queue:
            name = "{i}".format(i="%06d" % other_fuzzer_counter)
            currentDest = os.path.join(sync_dir, name)
            print sha1file(f)
            print "Copying %s to %s" % (f, currentDest)
            try:
                copyfile(f, currentDest)
            except:
                print "Copying file failed." 
                return
            other_fuzzer_counter += 1
        else:
          print "No new queue files found in other fuzzers..."

    time.sleep(sleep_time)

def signal_handler(sig, frame):
  global terminateMe
  print('You pressed Ctrl+C!')
  terminateMe = True
  sys.exit(0)

parser = argparse.ArgumentParser(description="", prog="afl_wrapper.py")
parser.add_argument('--source', dest='source', help='Queue/source directory of fuzzer', nargs=1, required=True)
parser.add_argument('--afl-destination', dest="destination", help="Where to copy the afl-style renamed queue files", nargs=1, required=True)
parser.add_argument('--fuzzer-dirs', dest="fuzzer_dirs", nargs="*", help="Specify the directory where to find the queue files of other fuzzers (multiple dirs allowed)", required=False)
parser.add_argument('--sync-dir', dest="sync_dir", help="Where to copy the queue files of the other fuzzers", nargs=1, required=False)
parser.add_argument('--sleep', dest="sleep", help="How many seconds to sleep before checking queues again", nargs=1)
args = parser.parse_args()

signal.signal(signal.SIGINT, signal_handler)

src = args.source[0]
dest = args.destination[0]
fuzzer_dirs = None
if args.fuzzer_dirs:
  fuzzer_dirs = args.fuzzer_dirs
sync_dir = None
if args.sync_dir:
  sync_dir = args.sync_dir[0]
sleep_time = 10
if args.sleep:
  sleep_time = int(args.sleep[0])

print src
print dest
print fuzzer_dirs

while not terminateMe:
  try:
    watcher(src, dest, fuzzer_dirs, sync_dir, sleep_time)
  except Exception as e:
    print("Watcher died because of exception %s, restarting..." % str(e))
    pass