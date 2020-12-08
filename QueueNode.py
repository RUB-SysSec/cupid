#!/usr/bin/python

import re, os

def get_id_from_filename(filename):
  id_search = re.search('id:([0-9]*)', filename, re.IGNORECASE)
  if id_search is None:
    return None
  return int(id_search.group(1))

def get_src_id_from_filename(filename):
  src_search = re.search('src:([0-9]*)', filename, re.IGNORECASE)
  if not src_search or src_search.group(1) == '':
    return None
  return int(src_search.group(1))  

def get_sync_name_from_filename(filename):
  sync_search = re.search('sync:(.*?),', filename, re.IGNORECASE)
  if not sync_search:
    return None
  return sync_search.group(1) 

def get_rand_id_from_name(name):
  randid_search = re.search('[^0-9]([0-9]{1,})$', name, re.IGNORECASE)
  if not randid_search:
    return None
  return int(randid_search.group(1))

def get_fuzzer_name_from_file_path(path):
  fuzzer_name_search = re.search('\/sync\/(.*?)\/', path, re.IGNORECASE)
  if not fuzzer_name_search:
    return None
  return fuzzer_name_search.group(1)

def find_children(parent, queue):
  (parentFuzzer, parentFileID) = parent
  children = []
  for q in queue:
    if not is_afl_file(q):
      continue
    fileID = get_id_from_filename(q)
    srcID = get_src_id_from_filename(q)
    fuzzerName = get_fuzzer_name_from_file_path(q)
    if srcID is not None and fileID is not None and fuzzerName is not None \
      and fuzzerName == parentFuzzer and srcID == parentFileID:
      children.append((parentFuzzer, fileID))
  return children

def find_all_children(parent, queue):
  children = find_children(parent, queue)
  allChildren = []
  allChildren.extend(children)
  for c in children:
    grandchildren = find_all_children(c, queue)
    if len(grandchildren) != 0:
      allChildren.extend(grandchildren)
  return allChildren

class QueueNode:

  def __init__(self, filename):
    self.filename = filename
    self.parent = None
    self.children = []
    self.parse_filename(self.filename)

  def parse_filename(self, filename):
    self.fuzzer = get_fuzzer_name_from_file_path(filename)
    assert(self.fuzzer is not None)

    self.basename = os.path.basename(filename)
    
    if "id:" in self.basename:
      self.id_in_queue = get_id_from_filename(self.basename)

    self.has_parent = "src:" in self.basename
    self.parent_id = None
    if self.has_parent:
      self.parent_id = get_src_id_from_filename(self.basename)
      if self.parent_id is None:
        self.has_parent = False
      else:
        fuzzerName = get_fuzzer_name_from_file_path(filename)
        assert(fuzzerName is not None)
        self.parent_fuzzer = fuzzerName

    self.is_sync = "sync:" in self.basename
    if self.is_sync:
      if self.has_parent:
        parent_fuzzer_name = get_sync_name_from_filename(self.basename)
        assert(parent_fuzzer_name is not None)
        self.parent_fuzzer = parent_fuzzer_name
      else:
        self.parent_fuzzer = self.fuzzer

  def get_all_children(self):
    allChildren = []
    allChildren.extend(self.children)
    alreadyIterated = set([])
    stack = []
    stack.extend(self.children)
    # recursive is too deep, replaced by iteration (with custom stack)
    while len(stack) > 0:
      # current element is the one from the stack
      currentPtr = stack.pop()
      alreadyIterated.add(currentPtr)
      # get all children from that element
      allChildren.extend(currentPtr.children)
      for c in currentPtr.children:
        # now add the children to process them next
        if c not in alreadyIterated:
          stack.append(c)
    return allChildren

  def __repr__(self):
    return "%s (%s)" % (self.filename, self.children)

  def __hash__(self):
    return hash(self.filename)

  def __eq__(self, other):
    return self.filename == other.filename