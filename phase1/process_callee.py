from pygments.lexers.c_cpp import CLexer
import os
import json
import gzip
import pickle
from tqdm import tqdm
import multiprocessing
import random
import glob
from sklearn.model_selection import train_test_split
import multiprocessing
import itertools
import pickle
import random
import codecs
import subprocess
import re
import sys
from code_retrieval import code_retrieve

if __name__ == '__main__':

	
	# Parse command line arguments
	start_idx = 0
	max_workers = 1  # Default single-process (changed to commit-optimized, no longer need multi-threading)
	only_indices = None  # Optional: set of idx to process only
	
	if len(sys.argv) > 1:
		try:
			start_idx = int(sys.argv[1])
		except ValueError:
			start_idx = 0
	
	if len(sys.argv) > 2:
		arg2 = sys.argv[2]
		try:
			only_indices = set(int(x) for x in arg2.split(',') if x.strip() != '')
		except Exception:
			pass
	
	n_layer = 6
	
	inpath = ""
	outpath = os.path.join(os.getcwd(), 'data')
	repo_base_path = ""
	
	if not os.path.exists(repo_base_path):
		exit(1)
	
	available_repos = [d for d in os.listdir(repo_base_path) if os.path.isdir(os.path.join(repo_base_path, d)) and not d.startswith('.')]
	
	if len(available_repos) == 0:
		exit(1)
	
	code_retrieve(inpath, outpath, n_layer, repo_base_path, start_idx, max_workers)
