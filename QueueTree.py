#!/usr/bin/python

from QueueNode import *

class QueueTree:

  def __init__(self, queue):
    #print "init QueueTree"
    self.filenameMap = {}
    self.idToNode = {}
    # parse all files first, then build the structure (parents and children)
    for q in queue:
      self.add_node_by_filename(q)
    self.build_tree()

  def find_seeds_of_fuzzer(self, randID):
    pass

  def get_node(self, filename):
    assert(filename in self.filenameMap)
    return self.filenameMap[filename]

  def build_tree(self):
    # set parents and children of all nodes
    #print "build_tree"
    for f in self.filenameMap:
      node = self.filenameMap[f]
      if node.has_parent:# and node.is_sync:
        #print "finding node (%d, %d)" % (node.parent_fuzzer, node.parent_id)
        node.parent = self.find_node(node.parent_fuzzer, node.parent_id)
        #assert(node.parent is not None)
        if node.parent is not None:
          node.parent.children.append(node)

  def find_node(self, fuzzer, id_in_queue):
    # find node by fuzzer id and seed id
    '''for f in self.filenameMap:
      # make QueueNode parse the filename so we can extract information
      n = self.filenameMap[f]
      if n.fuzzer == fuzzer and n.id_in_queue == id_in_queue:
        return n'''
    if id_in_queue not in self.idToNode:
      return None
    for n in self.idToNode[id_in_queue]:
      if n.fuzzer == fuzzer:
        return n
    return None

  def add_node_by_filename(self, filename):
    n = QueueNode(filename)
    self.filenameMap[filename] = n
    if n.id_in_queue not in self.idToNode:
      self.idToNode[n.id_in_queue] = []
    self.idToNode[n.id_in_queue].append(n)

  def find_nodes_by_fuzzer(self, fuzzer):
    nodes = []
    for f in self.filenameMap:
      if self.filenameMap[f].fuzzer == fuzzer:
        nodes.append(self.filenameMap[f])
    return nodes

  # finds all the sync nodes that originated from the given fuzzer
  def find_sync_nodes_by_fuzzer(self, fuzzer):
    nodes = []
    for f in self.filenameMap:
      if self.filenameMap[f].fuzzer == fuzzer:
        for child in self.filenameMap[f].children:
          if child.is_sync:
            #print "added %s" % child
            nodes.append(self.filenameMap[f])
            break
    return nodes

  def __repr__(self):
    s = ""
    for f in self.filenameMap:
      s += "%s\n" % str(self.filenameMap[f])
    return s