#!/usr/bin/python

import copy
from QueueNode import *
from QueueTree import *
from config import *
from threading import Lock
import quickcov
from Fuzzer import *
from shutil import copyfile

fuzzerTypeToClass = {
  "afl": FuzzerAFL,
  "aflfast": FuzzerAFLFast,
  "fairfuzz": FuzzerFairFuzz,
  "radamsa": FuzzerRadamsa,
  "lafintel": FuzzerLAFIntel,
  "qsym": FuzzerQSYM,
  "honggfuzz": FuzzerHonggfuzz,
  "libfuzzer": FuzzerLibFuzzer
}

MIN_TIME = 0
MAX_TIME = 9999999999

class FuzzerManager:

  def __init__(self, binary, input_file=None, time_dict=None, time_dict_lock=None):
    self.binary = binary
    if binaryToArguments[self.binary] == '':
      self.binary_arguments = ['@@']
    else:
      self.binary_arguments = binaryToArguments[self.binary].split(' ') + ['@@']
    self.fuzzers = []
    if time_dict_lock is None:
      self.time_dict_lock = Lock()
    else:
      self.time_dict_lock = time_dict_lock
    self.input_file = input_file
    self.time_dict = time_dict
    self.start_time = get_unix_timestamp()
    (self.toolset, self.full_binary) = binaryToToolsetAndProject[binary]
    self.q = quickcov.QuickCov(os.path.join(QUICKCOV_PATH, self.full_binary), self.binary_arguments)

  def get_fuzzers_by_config(self, config):
    matching_fuzzers = []
    for fuzzer in self.fuzzers:
      all_matching = True
      for key in config.keys():
        if key not in fuzzer.config or fuzzer.config[key] != config[key]:
          all_matching = False
      if all_matching:
        matching_fuzzers.append(fuzzer)
    return matching_fuzzers

  def pause(self):
    for fuzzer in self.fuzzers:
      fuzzer.pause()

  def resume(self):
    for fuzzer in self.fuzzers:
      fuzzer.resume()

  def start(self):
    for fuzzer in self.fuzzers:
      fuzzer.start()

  def stop(self):
    for fuzzer in self.fuzzers:
      fuzzer.stop()

  def create_fuzzer(self, fuzzer_type):
    assert(fuzzer_type in fuzzerTypeToClass)
    return fuzzerTypeToClass[fuzzer_type](self.binary, input_file=self.input_file, q=self.q)

  def add(self, fuzzer):
    self.fuzzers.append(fuzzer)
    fuzzer.fuzzer_manager = self

  def remove(self, fuzzer):
    self.fuzzers = list(filter(lambda x: x != fuzzer, self.fuzzers))
    fuzzer.fuzzer_manager = None

  # synchronize all fuzzers: copy all queue files to all fuzzers
  # we can't force them to read the sync dir, but it's just a 
  # matter of time.
  # => this guarantees only that fuzzers are unable to synchronize
  # BEFORE this call, but we don't know when they'll sync AFTER
  # this call
  def synchronize(self):
    queue_files = []
    hash_to_queue_file = {}
    for fuzzer in self.fuzzers:
      queue_dir = os.path.join(fuzzer.output_directory, fuzzer.docker_name, "queue")
      if not os.path.isdir(queue_dir):
        continue
      current_queue_files = [q for q in get_queue_files(queue_dir) if ".state" not in q]
      for q in current_queue_files:
        hash_to_queue_file[sha1file(q)] = q
      queue_files.extend(current_queue_files)
    #
    global_sync_files = get_queue_files(fuzzer.global_sync_dir)
    global_sync_files_hashes = [sha1file(q) for q in global_sync_files]
    hash_to_queue_file = {h: q for (h,q) in hash_to_queue_file.items() if h not in global_sync_files_hashes}
    counter = len(global_sync_files)
    for q in hash_to_queue_file.values():
      name = "id:{i},src:000000,op:syc".format(i="%06d" % counter)
      copyfile(q, os.path.join(self.fuzzers[0].global_sync_dir, "queue", name))
      #print("copying %s to %s" % (q, os.path.join(fuzzer.global_sync_dir, name)))
      counter += 1

  def get_coverage_files(self):
    files = []
    for fuzzer in self.fuzzers:
      files.extend(fuzzer.get_coverage_files())
    return files

  def _file_in_time(self, file, min_time, max_time):
    assert(file.startswith("/")) # needs to be an absolute path
    in_time = False
    ignore_this = False
    if self.time_dict is not None and file in self.time_dict:
      timestamp = self.time_dict[file]
    else:
      try:
        timestamp = os.path.getmtime(file)
      except:
        ignore_this = True
    if not ignore_this and min_time <= timestamp <= max_time:
      in_time = True
    return in_time

  def _filter_files_by_time(self, files, min_time, max_time):
    in_time_files = []
    for file in files:
      if self._file_in_time(file, min_time, max_time):
        in_time_files.append(file)
    return in_time_files

  def _get_coverage_for_files(self, files):
    (plot, bitmap, final_coverage) = self.q.get_coverage(files, plot=False, 
                                                         time_dict=self.time_dict, 
                                                         time_dict_lock=self.time_dict_lock,
                                                         minimum_time=self.start_time)
    return bitmap

  # get coverage (for fuzzer, if not None, for specified time period if set)
  def get_coverage(self, fuzzer=None, min_time=MIN_TIME, max_time=MAX_TIME, only_afl_queue=True):
    if fuzzer is not None:
      check_fuzzers = [fuzzer]
    else:
      check_fuzzers = self.fuzzers
    files = []
    for fuzzer in check_fuzzers:
      cov_files = fuzzer.get_coverage_files()
      files.extend(self._filter_files_by_time(cov_files, min_time, max_time))
    if only_afl_queue:
      files = filter_only_afl_queue_files(files)
    return self._get_coverage_for_files(files)

  def get_impact(self, fuzzer, min_time=MIN_TIME, max_time=MAX_TIME):
    cov_files = filter_only_afl_files(self.get_coverage_files())
    root = QueueTree(cov_files)
    sync_seeds = []
    for sync_name in fuzzer.get_sync_names():
      sync_seeds.extend(root.find_sync_nodes_by_fuzzer(sync_name))
    queue = set([])
    for s in sync_seeds:
      queue.add(s.filename)
      queue.update(set([x.filename for x in s.get_all_children()]))
    queue = self._filter_files_by_time(list(queue), min_time, max_time)
    return self._get_coverage_for_files(queue)

  def get_total_coverage(self, filter_redundant_files=True):
    # we don't want any sync files
    queue_files = get_queue_files(GLOBAL_OUTPUT_DIRECTORY)
    print("before: %d" % len(queue_files))
    if filter_redundant_files:
      queue_files = [f for f in queue_files if "/sync/" not in f and ".state" not in f]
    print("after: %d" % len(queue_files))
    d = copy.deepcopy(self.time_dict)
    (plot, bitmap, final_coverage) = self.q.get_coverage(queue_files, 
                                                         plot=True, 
                                                         relative_time=True,
                                                         time_dict=d, 
                                                         minimum_time=self.start_time)
    return (plot, bitmap, final_coverage)

  def __del__(self):
    self.cleanup()

  def cleanup(self):
    print("FuzzerManager cleanup")
    self.stop()
    try:
      self.q.cleanup()
    except Exception as e:
      print("Exception: cleaning QuickCov failed: %s" % str(e))