#!/usr/bin/python

from misc import *
from config import *
from stop import *
from CoreManager import *
import quickcov
import json, hashlib

"""
fuzzer.init(binary, binary_arguments)
fuzzer.pause() # pause docker image
fuzzer.start() # start/resume docker image 
fuzzer.update(config={"core": 0}) #update the configuration of this fuzzer (i.e. set core to 0, set cpu share percentage to 20% etc.)
fuzzer.setCore(0) # easier access to often-used configuration options
fuzzer.getType() # "afl", "qsym" etc.
fuzzer.getID() # the id of this specific fuzzer object (also used as a directory path)
fuzzer.getCoverageFiles() # returns all files relevant for code coverage measurement
fuzzer.getCoverage(files=None) # if files=None, go through all folders and return code coverage, if files is list, get code coverage for these files (Code Coverage is quickcov.AFLBitmap)
"""


DOCKER_COMMAND = 'docker exec --user coll -u {user_id}:{group_id} -t {docker_name} bash -ic "{cmd}"'

GLOBAL_INPUT_DIRECTORY  = get_input_dir()
GLOBAL_OUTPUT_DIRECTORY = get_sync_dir()
EVAL_SEED_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), "docker/misc/data/eval_seeds")

class AFLHierarchy(Enum):
  MASTER = 0
  SLAVE = 1

class Fuzzer:
  fuzzer_id = 0

  def __init__(self, binary, input_file=None, q=None):
    self.set_binary(binary)
    self.config = {}
    self.directories = []
    self.start_time = get_unix_timestamp()
    self.fuzzer_manager = None

    self.id = Fuzzer.fuzzer_id
    self.sync_id = get_sync_id()
    Fuzzer.fuzzer_id += 1
    
    self.input_directory  = GLOBAL_INPUT_DIRECTORY
    self.input_file = input_file
    self._setup_input_directory()
    self.output_directory = GLOBAL_OUTPUT_DIRECTORY
    if not os.path.isdir(self.output_directory):
      os.makedirs(self.output_directory)

    self._setup_output_directory()

    if q is None:
      self.q = quickcov.QuickCov(os.path.join(QUICKCOV_PATH, self.full_binary), self.binary_arguments)
    else:
      self.q = q
    
    self.init_config()
    self.init_names()

  def init_names(self):
    self.docker_name = "fuzzer-{type}-{id}-{sync_id}".format(type=self.type, id=self.id, sync_id=self.sync_id)
    self.docker_build = "fuzzer-{type}".format(type=self.type)
    self.directories.append(os.path.join(self.output_directory, self.docker_name))
    self.config["docker_name"] = self.docker_name
    self.config["docker_build"] = self.docker_build

  def init_config(self):
    self.config["binary"] = self.binary
    self.config["binary_arguments"] = self.binary_arguments
    self.config["core"] = 0
    self.config["type"] = self.type
    self.config["cpu_share"] = 1

  def get_file_placeholder(self):
    return ''

  def set_binary(self, binary):
    self.binary = binary
    self.binary_arguments = binaryToArguments[binary].split(' ') + [self.get_file_placeholder()]
    (self.toolset, self.full_binary) = binaryToToolsetAndProject[binary]

  def pause(self):
    os.system("docker pause {docker_name} > /dev/null 2>&1".format(docker_name=self.docker_name))
    while int(get_shell('docker container ls | grep %s$ | grep -i paused | wc -l' % self.docker_name) == 0):
      time.sleep(1)
    self.config["running"] = False

  def resume(self):
    os.system("docker unpause {docker_name} > /dev/null 2>&1".format(docker_name=self.docker_name))
    while int(get_shell('docker container ls | grep %s$ | grep -iv paused | wc -l' % self.docker_name) == 0):
      time.sleep(1)
    self.config["running"] = True

  def start(self):
    self.config["running"] = True

  def stop(self):
    os.system("docker stop {docker_name} > /dev/null 2>&1".format(docker_name=self.docker_name))
    os.system("docker rm {docker_name} > /dev/null 2>&1".format(docker_name=self.docker_name))
    self.config["running"] = False

  def _setup_input_directory(self):
    if self.input_file is None and self.binary in binaryToInputDirectory:
      # input directory or files are already given (i.e. LAVA-M), use that
      self.input_directory = binaryToInputDirectory[self.binary]
    else:
      # no input directory or files are missing, create basic seed
      if not os.path.isdir(self.input_directory):
        os.mkdir(self.input_directory)
        seed = os.path.join(self.input_directory, "a.bin")
        eval_seed_path = os.path.join(EVAL_SEED_PATH, self.full_binary)
        with open(seed, "wb+") as f:
          if self.input_file is None or not os.path.isfile(os.path.join(eval_seed_path, self.input_file)):
            # start with empty seed if no input file was specified (or input file does not exist)
            f.write(bytearray([0x00]))
          else:
            # else, use the specified eval seed
            with open(os.path.join(eval_seed_path, self.input_file), "rb") as inpf:
              f.write(inpf.read())


  def _setup_output_directory(self):
    if not os.path.isdir(self.output_directory):
      os.mkdir(self.output_directory)

  def _setup_docker_image(self):
    memory_limit_str = self.config.get('memory_limit', '')
    s = 'docker run --cpus=1 --cpuset-cpus="{core}" --ipc="host" ' \
        '-u {user_id}:{group_id} ' \
        '--cap-add=SYS_PTRACE --security-opt seccomp=unconfined {memory_limit_str} ' \
        '--name={docker_name} -td {docker_build}  > /dev/null 2>&1'.format(
                                        core=CoreManager().core[self.config["core"]],
                                        user_id=os.getuid(),
                                        group_id=os.getgid(), 
                                        docker_build=self.docker_build, 
                                        memory_limit_str=memory_limit_str, 
                                        docker_name=self.docker_name)
    print(s)
    os.system(s)

  def _exec_in_screen(self, cmd):
    os.system("screen -dmS {docker_name} bash -c '{command}' > /dev/null 2>&1".format(docker_name=self.docker_name,
                                                                     command=cmd))

  def _get_other_fuzzer_dirs(self):
    # fuzzer_dirs = []
    # if self.fuzzer_manager is not None:
    #   print(self.fuzzer_manager.fuzzers)
    #   for f in self.fuzzer_manager.fuzzers:
    #     if f != self:
    #       print(f.directories)
    #       for d in f.directories:
    #         if os.path.isdir(d):
    #           fuzzer_dirs.append(d)
    #         queue_subdir = os.path.join(d, "queue")
    #         if os.path.isdir(queue_subdir):
    #           fuzzer_dirs.append(queue_subdir)
    # fuzzer_dirs = list(set(fuzzer_dirs))
    # return fuzzer_dirs
    return [self.output_directory]


  def set_config_value(self, key, value):
    self.config[key] = value
    self._update()

  def update(self, config):
    self.config.update(config)
    self._update()

  def _update(self):
    os.system('docker update --cpuset-cpus="{core}" {docker_name} > /dev/null 2>&1'.format(core=CoreManager().core[self.config["core"]], docker_name=self.docker_name))
    os.system('docker update --cpus="{share}" {docker_name} > /dev/null 2>&1'.format(share="%.02f" % self.config["cpu_share"], docker_name=self.docker_name))

  def set_core(self, core):
    self.update({"core": core})

  def set_cpu_share(self, share):
    if share <= 0.01:
      self.pause()
    else:
      self.resume()
    self.update({"cpu_share": share})

  def get_type(self):
    return self.config["type"]

  def get_coverage_files(self):
    files = []
    for d in self.directories:
      files.extend(get_queue_files(d))
    return files

  def get_coverage(self, files=None, only_afl_queue=True):
    if files is None:
      files = self.get_coverage_files()
    if only_afl_queue:
      files = filter_only_afl_queue_files(files)
    (plot, bitmap, final_coverage) = self.q.get_coverage(files, plot=False, minimum_time=self.start_time)
    return bitmap

  def get_sync_names(self):
    return [self.docker_name]

  def __del__(self):
    self.q.cleanup()

  def __hash__(self):
    return hash(self.id)

  def __repr__(self):
    return self.docker_name

class FuzzerAFLType(Fuzzer):

  def __init__(self, binary, input_file=None, q=None):
    self.afl_directory = AFL_DIRECTORIES[self.type]
    self.hierarchy = AFLHierarchy.SLAVE
    super().__init__(binary, input_file=input_file, q=q)

  def init_config(self):
    super().init_config()
    self.config["hierarchy"] = self.hierarchy

  def init_names(self):
    if self.config["hierarchy"] == AFLHierarchy.MASTER:
      self.docker_name = "fuzzer-{type}-{id}-{sync_id}".format(type=self.type, id=self.id, sync_id=self.sync_id)
    else:
      self.docker_name = "fuzzer-{type}-slave-{id}-{sync_id}".format(type=self.type, id=self.id, sync_id=self.sync_id)
    self.docker_build = "fuzzer-{type}".format(type=self.type)
    self.directories.append(os.path.join(self.output_directory, self.docker_name))
    self.config["docker_name"] = self.docker_name
    self.config["docker_build"] = self.docker_build

  def get_file_placeholder(self):
    return '@@'

  def _afl_additional_argument(self):
    return ''

  def _afl_additional_environment_arguments(self):
    return ''

  def _afl_toolset_paths(self):
    return toolsetPaths

  def set_master(self):
    self.config["hierarchy"] = AFLHierarchy.MASTER

  def set_slave(self):
    self.config["hierarchy"] = AFLHierarchy.SLAVE

  def start(self):
    super()._setup_docker_image()
    binary_path = self._afl_toolset_paths()[self.toolset].format(binary=self.binary, 
                                                                 full_binary=self.full_binary,
                                                                 tail=binaryTails.get(self.binary, ""))
    binary_arguments = ' '.join(self.binary_arguments)
    binary_command = "{binary_path} {binary_arguments}".format(binary_path=binary_path, 
                                                               binary_arguments=binary_arguments)
    
    if self.config["hierarchy"] == AFLHierarchy.MASTER:
      sync_command = '-M {docker_name}'
    else: 
      sync_command = '-S {docker_name}'
    sync_command = sync_command.format(docker_name=self.docker_name)

    fuzzerCommand = "cd {binary_dir}; export {additional_env}; " \
                    "AFL_NO_AFFINITY=1 {additional_env} {afl_directory}/afl-fuzz {sync_command} -i {input_dir} " \
                    "-o {output_dir} -m none {additional_arg} -- {binary_command}" \
                    .format(afl_directory=self.afl_directory, sync_command=sync_command, binary=self.binary,
                      binary_command=binary_command, input_dir=self.input_directory, 
                      output_dir=self.output_directory, additional_arg=self._afl_additional_argument(),
                      additional_env=self._afl_additional_environment_arguments(), binary_dir=os.path.dirname(binary_path))
    s = DOCKER_COMMAND.format(docker_name=self.docker_name, cmd=fuzzerCommand, user_id=os.getuid(), group_id=os.getgid())
    print(s)
    self._exec_in_screen(s)
    self.config["running"] = True

class FuzzerAFL(FuzzerAFLType):

  def __init__(self, binary, input_file=None, q=None):
    self.type = "afl"
    super().__init__(binary, input_file=input_file, q=q)

class FuzzerAFLFast(FuzzerAFLType):
  def __init__(self, binary, input_file=None, q=None):
    self.type = "aflfast"
    super().__init__(binary, input_file=input_file, q=q)

class FuzzerFairFuzz(FuzzerAFLType):
  def __init__(self, binary, input_file=None, q=None):
    self.type = "fairfuzz"
    super().__init__(binary, input_file=input_file, q=q)

class FuzzerRadamsa(FuzzerAFLType):
  def __init__(self, binary, input_file=None, q=None):
    self.type = "radamsa"
    super().__init__(binary, input_file=input_file, q=q)

  def _afl_additional_argument(self):
    return '-R'

class FuzzerLAFIntel(FuzzerAFLType):
  def __init__(self, binary, input_file=None, q=None):
    self.type = "lafintel"
    super().__init__(binary, input_file=input_file, q=q)

  def _afl_additional_environment_arguments(self):
    return 'AFL_PRELOAD=/home/coll/AFLplusplus/libcompcov.so AFL_COMPCOV_LEVEL=2'

  def _afl_additional_argument(self):
    return '-t 1000000 -Q'

  def _afl_toolset_paths(self):
    return toolsetPathsUninstrumentedLafintel

class FuzzerQSYM(FuzzerAFLType):
  def __init__(self, binary, input_file=None, q=None):
    self.type = "qsym"
    super().__init__(binary, input_file=input_file, q=q)

  def init_names(self):
    super().init_names()
    self.qsym_name = "fuzzer-q-{id}".format(id=self.id)
    self.directories.append(os.path.join(self.output_directory, self.qsym_name))

  def start(self):
    super()._setup_docker_image()
    binary_path = toolsetPaths[self.toolset].format(binary=self.binary, 
                                                    full_binary=self.full_binary,
                                                    tail=binaryTails.get(self.binary, ""))
    # QSYM needs the uninstrumented binary, let's check if we have access to that
    if self.toolset in toolsetPathsUninstrumented:
      uninstrumented_binary_path = toolsetPathsUninstrumented[self.toolset].format(binary=self.binary, 
                                                                                   full_binary=self.full_binary,
                                                                                   tail=binaryTails.get(self.binary, ""))
    else:
      uninstrumented_binary_path = binary_path

    binary_arguments = ' '.join(self.binary_arguments)
    binary_command = "{binary_path} {binary_arguments}".format(binary_path=binary_path, 
                                                               binary_arguments=binary_arguments)
    uninstrumented_binary_command = "{binary_path} {binary_arguments}".format(binary_path=uninstrumented_binary_path, 
                                                                              binary_arguments=binary_arguments)
    if self.config["hierarchy"] == AFLHierarchy.MASTER:
      sync_command = '-M {docker_name}'
    else: 
      sync_command = '-S {docker_name}'
    sync_command = sync_command.format(docker_name=self.docker_name)
    
    qsym_output_directory = self.output_directory

    fuzzerCommand = "cd {binary_dir}; AFL_NO_AFFINITY=1 {afl_directory}/afl-fuzz {sync_command} -i {input_dir} " \
                    "-o {output_dir} -m none {additional_arg} -- {binary_command}" \
                    .format(afl_directory=self.afl_directory, sync_command=sync_command, binary=self.binary,
                      binary_command=binary_command, input_dir=self.input_directory, 
                      output_dir=qsym_output_directory, additional_arg=self._afl_additional_argument(), 
                      binary_dir=os.path.dirname(binary_path))

    fuzzerCommand += " & "
    fuzzerCommand += "sleep 20; cd {afl_directory}; python /workdir/qsym/bin/run_qsym_afl.py -a {docker_name} " \
                     "-o {output_dir} -n {qsym_name} -- {uninstrumented_binary_command}" \
                     .format(docker_name=self.docker_name, output_dir=qsym_output_directory,
                             qsym_name=self.qsym_name, uninstrumented_binary_command=uninstrumented_binary_command,
                             afl_directory=self.afl_directory)
    s = DOCKER_COMMAND.format(docker_name=self.docker_name, cmd=fuzzerCommand, user_id=os.getuid(), group_id=os.getgid())
    print(s)
    self._exec_in_screen(s)
    self.config["running"] = True

  def get_sync_names(self):
    return [self.docker_name, self.qsym_name]

class FuzzerHonggfuzz(Fuzzer):

  def __init__(self, binary, input_file=None, q=None):
    self.type = "honggfuzz"
    super().__init__(binary, input_file=input_file, q=q)
    self.honggfuzz_workspace      = os.path.abspath(os.path.join(self.output_directory, "honggfuzz-%d-ws-%s" % (self.id, self.sync_id)))
    self.honggfuzz_crash_dir      = os.path.abspath(os.path.join(self.output_directory, "honggfuzz-%d-crash-%s" % (self.id, self.sync_id)))
    self.honggfuzz_cov_dir        = os.path.abspath(os.path.join(self.output_directory, "honggfuzz-%d-cov-%s" % (self.id, self.sync_id)))
    self.honggfuzz_simulated_sync = os.path.abspath(os.path.join(self.output_directory, "honggfuzz-%d-sync-%s" % (self.id, self.sync_id)))
    self.honggfuzz_sync_name      = "fuzzer-honggfuzz-%d-%s" % (self.id, self.sync_id)
    self.directories.extend([self.honggfuzz_workspace, self.honggfuzz_crash_dir, self.honggfuzz_cov_dir, self.honggfuzz_simulated_sync])

  def get_file_placeholder(self):
    return '___FILE___'

  def start(self):
    super()._setup_docker_image()
    binary_path = toolsetPathsHonggfuzz[self.toolset].format(binary=self.binary, 
                                                             full_binary=self.full_binary,
                                                             tail=binaryTails.get(self.binary, ""))
    binary_arguments = ' '.join(self.binary_arguments)
    binary_command = "{binary_path} {binary_arguments}".format(binary_path=binary_path, 
                                                               binary_arguments=binary_arguments)

    # get queue folders of the other fuzzers
    fuzzer_dirs = self._get_other_fuzzer_dirs()
    fuzzer_dirs_str = ""
    if len(fuzzer_dirs) > 0:
      fuzzer_dirs_str = "--fuzzer-dirs %s" % ' '.join(fuzzer_dirs)

    fuzzerCommand = "mkdir -p {workspace_dir} {crash_dir} {cov_dir} {honggfuzz_simulated_sync}; cd {binary_dir};" \
                    "/home/coll/honggfuzz/honggfuzz --input {input_dir} " \
                    "--workspace {workspace_dir} --crashdir {crash_dir} --covdir_all {cov_dir} -n 1 -y {honggfuzz_simulated_sync} -Y 60 " \
                    "-- {binary_command} & " \
                    "sleep 10; python /home/coll/afl_wrapper.py --source {cov_dir} --afl-destination {output_dir}/{sync_name} {fuzzer_dirs_str} --sync-dir {honggfuzz_simulated_sync} --sleep 30" \
                    .format(binary=self.binary,
                            binary_command=binary_command, 
                            input_dir=self.input_directory, 
                            workspace_dir=self.honggfuzz_workspace,
                            crash_dir=self.honggfuzz_crash_dir,
                            cov_dir=self.honggfuzz_cov_dir,
                            output_dir=self.output_directory,
                            sync_name=self.honggfuzz_sync_name,
                            honggfuzz_simulated_sync=self.honggfuzz_simulated_sync,
                            fuzzer_dirs_str=fuzzer_dirs_str, 
                            binary_dir=os.path.dirname(binary_path))
    s = DOCKER_COMMAND.format(docker_name=self.docker_name, cmd=fuzzerCommand, user_id=os.getuid(), group_id=os.getgid())
    print(s)
    self._exec_in_screen(s)
    self.config["running"] = True

  def stop(self):
    os.system("docker stop {docker_name} > /dev/null 2>&1 &".format(docker_name=self.docker_name))
    time.sleep(5)
    os.system("docker rm {docker_name} > /dev/null 2>&1 &".format(docker_name=self.docker_name))
    time.sleep(5)
    os.system("pkill -f -9 %s" % self.docker_name)
    self.config["running"] = False

  def pause(self):
    pass


class FuzzerLibFuzzer(Fuzzer):
  def __init__(self, binary, input_file=None, q=None):
    self.type = "libfuzzer"
    super().__init__(binary, input_file=input_file, q=q)
    self.libfuzzer_cov_dir        = os.path.abspath(os.path.join(self.output_directory, "libfuzzer-%d-cov-%s" % (self.id, self.sync_id)))
    self.libfuzzer_crash_dir      = os.path.abspath(os.path.join(self.output_directory, "libfuzzer-%d-crash-%s" % (self.id, self.sync_id)))
    self.libfuzzer_simulated_sync = os.path.abspath(os.path.join(self.output_directory, "libfuzzer-%d-sync-%s" % (self.id, self.sync_id)))
    self.libfuzzer_sync_name      = "fuzzer-libfuzzer-%d-%s" % (self.id, self.sync_id)
    self.directories.extend([self.libfuzzer_cov_dir, self.libfuzzer_crash_dir, self.libfuzzer_simulated_sync])

  def get_file_placeholder(self):
    return ''

  def start(self):
    super()._setup_docker_image()

    binary_path = toolsetPathsLibfuzzer[self.toolset].format(binary=self.binary, 
                                                             full_binary=self.full_binary,
                                                             tail=binaryTails.get(self.binary, ""))
    binary_arguments = ' '.join(self.binary_arguments)

    # get queue folders of the other fuzzers
    fuzzer_dirs = self._get_other_fuzzer_dirs()
    fuzzer_dirs_str = ""
    if len(fuzzer_dirs) > 0:
      fuzzer_dirs_str = "--fuzzer-dirs %s" % ' '.join(fuzzer_dirs)

    fuzzerCommand = "mkdir -p {cov_dir} {libfuzzer_simulated_sync} {crash_dir}; cd {binary_dir}; " \
                    "{binary_path} -fork=1 -ignore_crashes=1 -artifact_prefix={crash_dir}/ {cov_dir} {input_dir} {libfuzzer_simulated_sync} " \
                    " & sleep 10; python /home/coll/afl_wrapper.py --source {cov_dir} --afl-destination {output_dir}/{sync_name} {fuzzer_dirs_str} " \
                    "--sync-dir {libfuzzer_simulated_sync} --sleep 30" \
                    .format(binary=self.binary,
                            binary_path=binary_path, 
                            input_dir=self.input_directory, 
                            output_dir=self.output_directory,
                            crash_dir=self.libfuzzer_crash_dir,
                            id=self.id,
                            sync_id=self.sync_id,
                            cov_dir=self.libfuzzer_cov_dir,
                            sync_name=self.libfuzzer_sync_name,
                            fuzzer_dirs_str=fuzzer_dirs_str,
                            libfuzzer_simulated_sync=self.libfuzzer_simulated_sync, 
                            binary_dir=os.path.dirname(binary_path))
    s = DOCKER_COMMAND.format(docker_name=self.docker_name, cmd=fuzzerCommand, user_id=os.getuid(), group_id=os.getgid())
    print(s)
    self._exec_in_screen(s)
    self.config["running"] = True