#!/usr/bin/python

import os, multiprocessing, shutil, glob, sys, re
from pathlib import Path
from config import *
from misc import *

def stop_fuzzer(fuzzer, sync_id):
  eval_names = find_docker(fuzzer, sync_id)
  for eval_name in eval_names:
    for a in range(3):
      os.system("screen -S {eval_name} -X stuff $'\\003' > /dev/null 2>&1".format(eval_name=eval_name))
    os.system("screen -X -S {eval_name} quit > /dev/null 2>&1".format(eval_name=eval_name))
    os.system("docker stop {eval_name} > /dev/null 2>&1; docker rm {eval_name} > /dev/null 2>&1".format(eval_name=eval_name))

def find_docker(fuzzer, sync_id):
  active_docker_containers = get_shell(f'docker ps --no-trunc -a | grep "\\-{sync_id}"').decode('ascii').split("\n")
  running_docker = []
  for active_docker_container in active_docker_containers:
    r = re.findall(f"(fuzzer-{fuzzer}-[a-zA-Z0-9\\-]*?-{sync_id})", active_docker_container, re.MULTILINE)
    if r:
      running_docker.append(r)
  return running_docker

def derive_sync_ids_from_folder():
  # sync* ids
  sync_dirs = glob.glob("/dev/shm/sync*/")
  sync_ids = []
  for sync_dir in sync_dirs:
    sync_id = Path(sync_dir).name.replace('sync', '')
    sync_ids.append(sync_id)
  return sync_ids

def kill_all_fuzzers(sync_id=None):
  if sync_id is None:
    sync_ids = derive_sync_ids_from_folder()
  else:
    sync_ids = [sync_id]
  for sync_id in sync_ids:
    for f in fuzzers:
      stop_fuzzer(f, sync_id=sync_id)

  # clean up unused ipcs'
  os.system("ipcs -m | grep '\\(65536\\|1048576\\).*0 ' | tr -s ' ' | cut -d' ' -f 2 | xargs -I _ ipcrm -m _")

def delete_shm_sync(sync_id):
  sync_dir = "/dev/shm/sync%s/" % sync_id
  outside_dirs = glob.glob("/dev/shm/%s-*" % sync_id) + ["/dev/shm/inp%s/" % sync_id]
  for d in [sync_dir] + outside_dirs:
    if os.path.isdir(d):
      shutil.rmtree(d)

def delete_llvm_fuzz_files():
  fuzz_files = "/dev/shm/fuzz-*"
  for f in glob.glob(fuzz_files):
    os.remove(f)

def delete_quickcov_files():
  quickcov_files = "/dev/shm/quickcov_*"
  for f in glob.glob(quickcov_files):
    os.remove(f)

def kill_all():
  # this is sometimes the only way to properly clean up.
  os.system("timeout -k 5 20 sudo service docker restart")
  # free all afl shared memories
  os.system("ipcs -m | grep '\\(65536\\|1048576\\).*0 ' | tr -s ' ' | cut -d' ' -f 2 | xargs -I _ ipcrm -m _")
  # kill honggfuzz because it hangs all the time
  os.system("pkill -f -9 /dev/shm/sync*/honggfuzz")
  # stop all docker containers
  os.system("docker stop $(docker ps -a -q) > /dev/null 2>&1")
  os.system("docker rm $(docker ps -a -q) > /dev/null 2>&1")
  os.system("docker network prune -f > /dev/null 2>&1")
  os.system("screen -wipe > /dev/null 2>&1")
  os.system("rm -f /dev/shm/cms")

if __name__ == "__main__":
  sync_id = None
  if 1 in sys.argv:
    sync_id = sys.argv[1]
    kill_all_fuzzers(sync_id)
  else:
    kill_all_fuzzers()
    kill_all()
    sync_ids = derive_sync_ids_from_folder()
    for sid in sync_ids:
      delete_shm_sync(sid)
    delete_llvm_fuzz_files()
    delete_quickcov_files()
  print("stop.py finished")
