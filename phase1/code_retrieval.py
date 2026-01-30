from pygments.lexers.c_cpp import CLexer
import os
import json
import gzip
import pickle
import multiprocessing
import random
import glob
import multiprocessing
import itertools
import pickle
import random
from tqdm import tqdm
import codecs
import subprocess
import re
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# File write lock for thread safety
write_lock = threading.Lock()


def generate_cscope_database(source_dir):
	"""
	Generate cscope database
	
	Returns:
		bool: Whether database generation succeeded
	"""
	# Clean old cscope database files (avoid residue)
	old_files = ['cscope.files', 'cscope.out', 'cscope.in.out', 'cscope.po.out']
	for old_file in old_files:
		try:
			if os.path.exists(old_file):
				os.remove(old_file)
		except:
			pass
	
	# Rescan all .c files in current commit
	result = subprocess.run(['find', '.', '-name', '*.c'], stdout=subprocess.PIPE, text=True)
	c_files = result.stdout.strip()
	
	# If no .c files found, return failure directly
	if not c_files:
		logger.debug("No .c files found, skipping cscope database generation")
		return False
	
	with open('cscope.files', 'w') as file:
		file.write(c_files)

	# Generate cscope database (redirect stderr to avoid warning pollution in logs)
	subprocess.run(
		['cscope', '-b', '-q', '-k', '-i', 'cscope.files'],
		stderr=subprocess.DEVNULL  # Ignore "cannot find file" warnings
	)
	
	# Check if cscope.out was successfully generated
	if not os.path.exists('cscope.out'):
		logger.warning("cscope database generation failed (cscope.out does not exist)")
		return False
	
	return True
# Get functions called by function_name
def get_callees(source_dir, function_name):
	# Check if cscope.out exists
	if not os.path.exists('cscope.out'):
		logger.warning("cscope.out does not exist, cannot query call relationships")
		return "", None
	
	result = subprocess.run(['cscope', '-dL2' + function_name], stdout=subprocess.PIPE, text=True, stderr=subprocess.DEVNULL)
	lines = result.stdout.splitlines()
	if len(lines) == 0:
		return "", None

	called_functions = []
	file_path = lines[0].split()[0]
	for line in lines:
		parts = line.split()
		if len(parts) > 1 and parts[0] == file_path and parts[1] not in called_functions :
			called_functions.append(parts[1])
		# print(line)
	return file_path, called_functions

def extract_func_name(file_path):
	"""
	Extract functions according to function name in file_path.
	"""	

	# Extract source code of function_name
	function_name = ""

	result = subprocess.run(['ctags', '--fields=+ne-t', '-o', '-', '--sort=no', '--excmd=number', str(file_path)], stdout=subprocess.PIPE, text=True)
	lines = result.stdout.splitlines()
	if len(lines) == 0:
		return function_name
	fields = lines[0].split()
	function_name = fields[0]
	return function_name

def extract_func(source_dir, file_path, function_name):
	result = subprocess.run(['ctags', '--fields=+ne-t', '-o', '-', '--sort=no', '--excmd=number', str(file_path)], stdout=subprocess.PIPE, text=True)
	lines = result.stdout.splitlines()
	for line in lines:
		fields = line.split()
		if 'f' in fields and fields[0] == function_name:
			start_num, end_num = extract_numbers(line)
			if start_num == None:
				return None
			try:
				func_str = extract_func_str(file_path, start_num, end_num)
				return func_str
			except:
				return None				
	return None

def extract_func_str(file_path, start_num, end_num):
	with open(file_path, "r", encoding='utf-8') as rfile:
		lines = rfile.readlines()
		return "".join(lines[start_num - 1:end_num])

def extract_numbers(text):
	pattern = r'line:(\d+).*end:(\d+)'
	
	match = re.search(pattern, text)
	
	if match:
		line_number = int(match.group(1))
		end_number = int(match.group(2))
		return line_number, end_number
	else:
		return None, None


def retrieve_callee(source_dir, commit_id, function_name, n_layer=None, current_commit=None):
	"""
	Retrieve function call relationships
	
	Args:
		source_dir: Source code directory
		commit_id: Target commit
		function_name: Function name
		n_layer: Maximum retrieval layers
		current_commit: Currently checked out commit (for determining if re-checkout is needed)
	
	Returns:
		tuple: (callees, checkout_status) 
		       - callees: Retrieved callee list
		       - checkout_status: True=successful checkout, False=reused index, None=checkout failed
	"""
	callees = []
	os.chdir(source_dir)
	
	# Check if checkout is needed (skip if commit is the same)
	need_checkout = (current_commit != commit_id)
	
	if need_checkout:
		# Try to checkout specified commit (skip directly on failure, no fetch)
		result = subprocess.run(['git', 'checkout', '-f', str(commit_id)], 
		                       capture_output=True, text=True)
		
		if result.returncode != 0:
			# Checkout failed, return None to indicate failure
			logger.debug(f"Git checkout failed, skipping (commit: {commit_id}): {result.stderr.strip()[:100]}")
			return callees, None  # ← Return None to indicate checkout failure
		
		# Checkout successful, rebuild cscope index
		if not generate_cscope_database(source_dir):
			logger.warning(f"cscope database generation failed, skipping (commit: {commit_id[:8]})")
			return callees, None  # ← Return None to indicate cscope failure
		logger.debug(f"✅ Checkout and rebuild index: {commit_id[:8]}")
	else:
		logger.debug(f"⚡ Reuse current commit index: {commit_id[:8]}")
	# Layer 1: Get functions directly called by function_name
	layer = 1
	funcs_temp = []
	cfs = []
	file_path, called_functions = get_callees(source_dir, function_name)
	if file_path == "":
		# logger.warning("No callees in root function.")
		# Return appropriate status: True if new checkout, False if reused
		return callees, (True if need_checkout else False)
	# Record Layer 1 called functions
	for called_function in called_functions:
		funcs_temp.append({'layer':layer,'func_name':called_function,'caller':function_name})
		cfs.append(called_function)
	while True:
		temp = []
		for func in funcs_temp:
			layer=func['layer']+1
			funcs_temp.remove(func)
			file_path, called_functions = get_callees(source_dir, func['func_name'])
			if file_path == "":
				continue
			func_str = extract_func(source_dir, file_path, func['func_name'])
			if func_str == None:
				continue
			callee = {'layer':func['layer'], 'func_name':func['func_name'], 'func_str':func_str, 'caller':func['caller']}
			callees.append(callee)
			for called_function in called_functions:
				if called_function not in cfs:
					cfs.append(called_function)
					temp.append({'layer':layer,'func_name':called_function,'caller':func['func_name']})
		funcs_temp=temp
		if len(funcs_temp) == 0:
			break
		if layer == n_layer:
			break
	# print(callees)
	# Return appropriate status: True if new checkout, False if reused
	return callees, (True if need_checkout else False)


def process_project_samples(project_name, project_samples, repo_base_path, n_layer, output_file):
	"""
	Process all samples of a single project (sorted by commit to reduce checkout count)
	
	Args:
		project_name: Project name
		project_samples: List of all samples for this project
		repo_base_path: Repository base path
		n_layer: Maximum retrieval layers
		output_file: Output file path
		
	Returns:
		dict: Statistics including success count, skip count, etc.
	"""
	source_dir = os.path.join(repo_base_path, project_name)
	
	# Check if repository exists
	if not os.path.exists(source_dir):
		logger.warning(f"[{project_name}] Repository does not exist, skipping {len(project_samples)} samples")
		return {
			'project': project_name,
			'total': len(project_samples),
			'success': 0,
			'skip_no_repo': len(project_samples),
			'skip_no_callee': 0,
			'error': 0,
			'checkouts': 0,
			'reused': 0
		}
	
	# 🔑 Key optimization: Sort by commit_id, samples with same commit will be processed consecutively
	sorted_samples = sorted(project_samples, key=lambda x: x['commit_id'])
	
	success_count = 0
	skip_no_callee = 0
	error_count = 0
	checkout_count = 0
	reuse_count = 0
	
	current_commit = None  # Track currently checked out commit
	
	logger.info(f"[{project_name}] Starting to process {len(sorted_samples)} samples (sorted by commit)")
	
	# Count how many unique commits
	unique_commits = len(set(s['commit_id'] for s in sorted_samples))
	logger.info(f"[{project_name}] Total {unique_commits} unique commits, expected {unique_commits} checkouts")
	
	total_samples = len(sorted_samples)
	processed_in_project = 0
	
	# Use tqdm to show progress
	progress_bar = tqdm(sorted_samples, desc=f"[{project_name}]", unit="samples")
	
	for data in progress_bar:
		idx = data['idx']
		processed_in_project += 1
		
		try:
			# Pass current_commit to let retrieve_callee determine if re-checkout is needed
			callees, checkout_status = retrieve_callee(
				source_dir, data['commit_id'], data['func_name'], n_layer, current_commit
			)
			
			# Update statistics (checkout_status: True=successful checkout, False=reused, None=failed)
			if checkout_status is True:
				# Successfully checked out and built index
				checkout_count += 1
				current_commit = data['commit_id']  # ✅ Update current commit
			elif checkout_status is False:
				# Reused current commit index
				reuse_count += 1
			elif checkout_status is None:
				# Checkout or cscope generation failed, record error but continue
				logger.debug(f"[{project_name}] idx={idx}: checkout/cscope failed, skipping")
				error_count += 1
				continue
			
			if len(callees) == 0:
				logger.debug(f"[{project_name}] idx={idx}: no callee, skipping")
				skip_no_callee += 1
				continue
			
			data['callee'] = callees
			
			# Write to file (single-threaded, no lock needed)
			with open(output_file, 'a', encoding='utf-8') as f:
				f.write(json.dumps(data) + '\n')
				f.flush()
			
			success_count += 1
			logger.debug(f"[{project_name}] idx={idx}: successfully retrieved {len(callees)} callees")
			
		except Exception as e:
			logger.warning(f"[{project_name}] idx={idx} processing error: {e}")
			error_count += 1
			continue
		
		# Update tqdm status information
		progress_bar.set_postfix({
			'success': success_count,
			'skip': skip_no_callee,
			'error': error_count,
			'checkout': checkout_count,
			'reuse': reuse_count
		})
	
	logger.info(f"[{project_name}] Complete! Success: {success_count}, Skip: {skip_no_callee}, Error: {error_count}")
	logger.info(f"[{project_name}] ⚡ Performance: {checkout_count} checkouts, {reuse_count} index reuses")
	
	return {
		'project': project_name,
		'total': len(sorted_samples),
		'success': success_count,
		'skip_no_repo': 0,
		'skip_no_callee': skip_no_callee,
		'error': error_count,
		'checkouts': checkout_count,
		'reused': reuse_count
	}


def load_processed_indices(output_file):
	"""
	Load list of already processed idx
	
	Args:
		output_file: Output file path
		
	Returns:
		set: Set of processed idx
	"""
	processed_indices = set()
	
	if not os.path.exists(output_file):
		logger.info(f"Output file does not exist, will start from beginning: {output_file}")
		return processed_indices
	
	try:
		with open(output_file, 'r', encoding='utf-8') as f:
			for line in f:
				if line.strip():
					try:
						data = json.loads(line)
						if 'idx' in data:
							processed_indices.add(data['idx'])
					except json.JSONDecodeError:
						continue
		
		# logger.info(f"Loaded {len(processed_indices)} processed idx")
		return processed_indices
	except Exception as e:
		logger.warning(f"Error loading processed idx: {e}")
		return processed_indices


def load_or_build_cache(file_path, cache_file, processed_indices, start_idx):
	"""
	Load cache or rebuild data
	
	Args:
		file_path: Input JSON file path
		cache_file: Cache file path
		processed_indices: Set of processed idx
		start_idx: Starting idx
		
	Returns:
		tuple: (datas, skipped_start_idx, skipped_processed, use_cache)
	"""
	# Check if cache is valid
	use_cache = False
	if os.path.exists(cache_file):
		cache_mtime = os.path.getmtime(cache_file)
		input_mtime = os.path.getmtime(file_path)
		
		# If cache is newer than input file, use cache
		if cache_mtime > input_mtime:
			try:
				logger.info(f"Loading cache file: {cache_file}")
				with open(cache_file, 'rb') as f:
					cached_data = pickle.load(f)
				
				# Verify cache data integrity
				if isinstance(cached_data, dict) and 'datas' in cached_data:
					all_datas = cached_data['datas']
					original_count = len(all_datas)
					logger.info(f"✅ Successfully loaded cache, total {original_count} samples")
					
					# Step 1: Remove processed samples from cache (update cache)
					if processed_indices:
						# logger.info(f"🔄 Removing {len(processed_indices)} processed samples from cache...")
						all_datas = [data for data in all_datas if data['idx'] not in processed_indices]
						removed_count = original_count - len(all_datas)
						
						if removed_count > 0:
							logger.info(f"✅ Removed {removed_count} samples from cache, {len(all_datas)} remaining")
							
							# Re-save updated cache
							try:
								# logger.info(f"💾 Saving updated cache...")
								with open(cache_file, 'wb') as f:
									pickle.dump({'datas': all_datas, 'version': 1}, f)
								logger.info(f"✅ Cache updated")
							except Exception as e:
								logger.warning(f"Failed to save updated cache: {e}")
					
					# Step 2: Filter data to be processed
					datas = []
					skipped_start_idx = 0
					skipped_processed = 0
					
					for data in all_datas:
						idx = data['idx']
						
						if idx < start_idx:
							skipped_start_idx += 1
							continue
						
						# No need to check processed_indices here, already removed from cache
						datas.append(data)
					
					use_cache = True
					logger.info(f"Cache filtering complete: kept {len(datas)} samples to process")
					return datas, skipped_start_idx, skipped_processed, use_cache
				
			except Exception as e:
				logger.warning(f"Failed to load cache, will re-parse: {e}")
	
	# Cache does not exist or invalid, re-parse
	logger.info("Starting to parse input file (no valid cache)...")
	
	instances = []
	with open(file_path, 'r') as f:
		for line in f:
			if line.strip():
				instances.append(json.loads(line))
	# Extract func_name for all samples (no filtering)
	all_datas = []
	dir = "/home/heyanquan/hyq/llm-sieve/data/temp"
	if not os.path.exists(dir):
		os.makedirs(dir)
	
	for i, item in tqdm(enumerate(instances), total=len(instances), desc="Parsing samples"):
		idx = item['idx']
		
		data = {}
		data['idx'] = idx
		data['target'] = item['target']
		data['project'] = item['project']
		data['commit_id'] = item['commit_id']
		data['file'] = str(item['target'])+"_"+str(item['project']) +"_"+str(item['commit_id'])+".c"
		data['func'] = item['func']
		
		filepath = os.path.join(dir, data['file'])
		function_name = extract_func_name(filepath)
		if function_name == "":
			continue
		
		data['func_name'] = function_name
		all_datas.append(data)
	
	# Save cache
	try:
		logger.info(f"Saving cache to: {cache_file}")
		with open(cache_file, 'wb') as f:
			pickle.dump({'datas': all_datas, 'version': 1}, f)
		logger.info(f"✅ Cache saved, total {len(all_datas)} samples")
	except Exception as e:
		logger.warning(f"Failed to save cache: {e}")
	
	# Filter data
	datas = []
	skipped_start_idx = 0
	skipped_processed = 0
	
	for data in all_datas:
		idx = data['idx']
		
		if idx < start_idx:
			skipped_start_idx += 1
			continue
		
		if idx in processed_indices:
			skipped_processed += 1
			continue
		
		datas.append(data)
	
	return datas, skipped_start_idx, skipped_processed, use_cache


def clean_git_locks(repo_base_path):
	"""Clean all Git lock files (prevent locks left by previously killed processes)"""
	logger.info("🧹 Cleaning Git lock files...")
	
	import glob
	from pathlib import Path
	
	# Find all .lock files under .git directories
	lock_pattern = str(Path(repo_base_path) / '*/.git/*.lock')
	lock_files = glob.glob(lock_pattern)
	
	if lock_files:
		logger.warning(f"Found {len(lock_files)} lock files, cleaning...")
		for lock_file in lock_files:
			try:
				os.remove(lock_file)
				logger.debug(f"  Deleted: {lock_file}")
			except Exception as e:
				logger.warning(f"  Failed to delete {lock_file}: {e}")
		logger.info(f"✅ Cleaned {len(lock_files)} lock files")
	else:
		logger.info("✅ No lock files found")


def code_retrieve(file_path, out, n_layer, repo_base_path=None, start_idx=0, max_workers=1):
	"""
	Code retrieval function, automatically match repositories by project name (single-process sequential processing, optimized by commit)
	
	Args:
		file_path: Input JSON file path
		out: Output directory
		n_layer: Maximum retrieval layers
		repo_base_path: Repository base path, default is out/repo
		start_idx: Start processing from specified idx (for resuming)
		max_workers: Reserved parameter for compatibility (now changed to single-process)
	"""
	if repo_base_path is None:
		repo_base_path = os.path.join(out, 'repo')
	
	# 🔧 Clean all Git lock files at startup
	clean_git_locks(repo_base_path)
	
	# Output file path
	output_file = os.path.join('')
	
	# Cache file path
	cache_file = os.path.join('')
	
	# Load processed idx
	processed_indices = load_processed_indices(output_file)
	logger.info(f"Will skip {len(processed_indices)} processed samples")
	
	# Load or build cache
	datas, skipped_start_idx, skipped_processed, use_cache = load_or_build_cache(
		file_path, cache_file, processed_indices, start_idx
	)
	
	logger.info("stage1: Sample parsing complete ===============")
	logger.info(f"Total parsed {len(datas)} samples to process")
	
	# Group samples by project
	logger.info(f"\nstage2: Grouping samples by project ===============")
	project_samples = {}
	for data in datas:
		project = data['project']
		if project not in project_samples:
			project_samples[project] = []
		project_samples[project].append(data)
	
	logger.info(f"Total {len(project_samples)} projects to process")
	logger.info(f"⚡ Using single-process sequential processing (optimized by commit sorting)")
	
	# Single-process sequential processing of all projects
	logger.info(f"\nstage2: Starting callee retrieval (processing by project order)===============")
	
	all_results = []
	completed = 0
	total_projects = len(project_samples)
	
	# 🔑 Sort by sample count from small to large: small projects first, large projects like Chrome processed last
	sorted_projects = sorted(project_samples.items(), key=lambda x: len(x[1]))
	
	# Use tqdm to show project-level progress
	project_progress = tqdm(sorted_projects, desc="Processing projects", unit="projects")
	
	for project, samples in project_progress:
		completed += 1
		project_progress.set_description(f"Project {project}")
		logger.info(f"[{project}] Starting to process {len(samples)} samples")
		
		try:
			result = process_project_samples(project, samples, repo_base_path, n_layer, output_file)
			all_results.append(result)
			logger.info(f"[{project}] ✅ Processing complete")
		except Exception as e:
			logger.error(f"[Progress {completed}/{total_projects}] ❌ Project '{project}' processing failed: {e}")
			all_results.append({
				'project': project,
				'total': len(samples),
				'success': 0,
				'skip_no_repo': 0,
				'skip_no_callee': 0,
				'error': len(samples),
				'checkouts': 0,
				'reused': 0
			})
	
	# Overall statistics
	logger.info(f"\nstage2: Callee retrieval complete ===============")
	total_success = sum(r['success'] for r in all_results)
	total_skip_no_callee = sum(r['skip_no_callee'] for r in all_results)
	total_skip_no_repo = sum(r['skip_no_repo'] for r in all_results)
	total_error = sum(r['error'] for r in all_results)
	total_processed = sum(r['total'] for r in all_results)
	total_checkouts = sum(r.get('checkouts', 0) for r in all_results)
	total_reused = sum(r.get('reused', 0) for r in all_results)
	
	logger.info(f"Total sample count: {total_processed}")
	logger.info(f"Successfully retrieved: {total_success} samples ({total_success*100.0/total_processed:.1f}%)")
	logger.info(f"Skipped (no callee): {total_skip_no_callee} samples")
	logger.info(f"Skipped (repository does not exist): {total_skip_no_repo} samples")
	logger.info(f"Errors: {total_error} samples")
	logger.info(f"\n⚡ Performance optimization statistics:")
	logger.info(f"  Git checkout: {total_checkouts} times")
	logger.info(f"  Index reuse: {total_reused} times")
	if total_checkouts + total_reused > 0:
		reuse_rate = total_reused * 100.0 / (total_checkouts + total_reused)
		logger.info(f"  Reuse rate: {reuse_rate:.1f}%")

