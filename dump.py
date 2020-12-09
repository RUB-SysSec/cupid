#!/usr/bin/python

import sys
import pprint
import pickle

def rec_dd():
    return defaultdict(rec_dd)

pp = pprint.PrettyPrinter(indent=4, compact=True)

with open(sys.argv[1], "rb") as f:
	data = pickle.load(f)
	pp.pprint(data)