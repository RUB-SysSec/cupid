#!/usr/bin/python

import os, subprocess, time, random, copy, glob, hashlib
import numpy, operator
from functools import reduce
from operator import mul
from collections import defaultdict

def check_afl():
  core_set = (open('/proc/sys/kernel/core_pattern', "r").read().strip() == "core")
  performance_set = True
  for filename in glob.glob('/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor'):
    with open(filename, "r") as f:
      performance_set = performance_set & (f.read().strip() == 'performance')
  return core_set & performance_set

def update_screenrc():
  screenrcPath = os.path.expanduser("~/.screenrc")
  if not os.path.isfile(screenrcPath) or "defnonblock on" not in open(screenrcPath, "r").read():
    os.system("echo defnonblock on >> %s" % screenrcPath)

def get_shell(cmd):
  process = subprocess.Popen(cmd, shell=True,
                             stdout=subprocess.PIPE, 
                             stderr=subprocess.PIPE)
  # wait for the process to terminate
  out, err = process.communicate()
  errcode = process.returncode
  return out

def get_queue_files(folder):
  files = []
  for d in os.listdir(folder):
    p = os.path.abspath(os.path.join(folder, d))
    if os.path.isdir(p):
      files.extend(get_queue_files(p))
    else:
      files.append(p)
  return files

def get_unix_timestamp():
  return int(time.time())

def check_for_new_files(directory, cache):
  files = get_queue_files(directory)
  t = get_unix_timestamp()
  newFiles = {}
  for f in files:
    if os.path.isdir(f):
      continue
    if f not in cache:
      newFiles[f] = t
  return newFiles

def is_afl_file(file_path):
  return os.path.basename(file_path).startswith("id:")

def is_afl_queue_file(file_path, filter_sync=True):
  ret = ('/queue/' in file_path and 
     '/.state/' not in file_path and 
     '/.synced/' not in file_path and
     is_afl_file(file_path))
  if filter_sync:
    ret = ret and ',sync:' not in os.path.basename(file_path)
  return ret

def filter_only_afl_files(files):
  return [f for f in files if is_afl_file(f)]

def filter_only_afl_queue_files(files):
  return [f for f in files if is_afl_queue_file(f)]

def get_pid():
  return os.getpid()

def get_sync_id():
  return str(os.getenv('SYNC_ID', default=get_pid()))

def get_sync_dir():
  return "/dev/shm/sync%s" % get_sync_id()

def get_input_dir():
  return "/dev/shm/inp%s" % get_sync_id()

# https://stackoverflow.com/questions/568271/how-to-check-if-there-exists-a-process-with-a-given-pid-in-python
def check_pid(pid):
  pid = int(pid)
  """ Check For the existence of a unix pid. """
  try:
      os.kill(pid, 0)
  except OSError:
      return False
  else:
      return True

# https://stackoverflow.com/questions/32295395/how-to-get-the-process-name-by-pid-in-linux-using-python
def pid_to_name(pid):
  p = subprocess.Popen(["ps -o cmd= {}".format(pid)], stdout=subprocess.PIPE, shell=True)
  return str(p.communicate()[0])

def sha1file(f):
  sha1sum = hashlib.sha1()
  with open(f, 'rb') as source:
    block = source.read(2**16)
    while len(block) != 0:
      sha1sum.update(block)
      block = source.read(2**16)
  return sha1sum.hexdigest()