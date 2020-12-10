#!/usr/bin/python

import os, pickle, multiprocessing, time
from misc import *
from pathlib import Path
from Singleton import *
from oslo_concurrency import lockutils
from oslo_concurrency import processutils

CM_BASEDIR = "/dev/shm"

class CoreManager(metaclass=Singleton):

  def __init__(self, num_fuzzers=None):
    if num_fuzzers is None and not hasattr(self, 'num_fuzzers'):
      self.num_fuzzers = multiprocessing.cpu_count()
    elif num_fuzzers is not None:
      self.num_fuzzers = num_fuzzers
    self.cms_path = os.path.join(CM_BASEDIR, 'cms')

    (cms, cores_found) = self.acquire_cores(num_fuzzers)
    while not cores_found:
      print("Not enough cores are available at the moment, trying again in 60s...")
      time.sleep(60)
      (cms, cores_found) = self.acquire_cores(num_fuzzers)
    # set up a mapping from fake core -> real core (i.e. asking core[0] will returm some actually available core)
    self.core = {core: available_core for core, available_core in zip(range(self.num_fuzzers), self.available_cores)}
    # dump our information so the next process can handle them
    cms.update({get_pid(): list(self.core.values())})
    with open(self.cms_path, "wb+") as f:
      pickle.dump(cms, f)

  @lockutils.synchronized('not_thread_process_safe', external=True, lock_path=CM_BASEDIR)
  def acquire_cores(self, num_cores):
    self.all_cores = list(range(multiprocessing.cpu_count()))
    self.occupied_cores = []

    # determine cores by looking up what everybody else uses (they all dump files with information)
    
    if os.path.isfile(self.cms_path):
      with open(self.cms_path, "rb+") as f:
        cms = pickle.load(f)
    else:
      cms = {}
    # filter out all pid's which exist even though the process doesn't exist anymore
    cms = {pid: cores for pid,cores in cms.items() if check_pid(pid) and "control.py" in pid_to_name(pid)}
    # load all information from every pid to determine the cores we can use
    for pid in cms:
      self.occupied_cores.extend(cms[pid])

    self.available_cores = list(set(self.all_cores) - set(self.occupied_cores))
    return (cms, (len(self.available_cores) >= num_cores))

  @lockutils.synchronized('not_thread_process_safe', external=True, lock_path=CM_BASEDIR)
  def cleanup(self):
    print("CoreManager cleanup")
    if os.path.isfile(self.cms_path):
      with open(self.cms_path, "rb+") as f:
        cms = pickle.load(f)
        if get_pid() in cms:
          del cms[get_pid()]
      with open(self.cms_path, "wb+") as f:
        pickle.dump(cms, f)

  #def __del__(self):
  #  self.cleanup()
