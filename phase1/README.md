# Phase 1: Code Retrieval

## Overview

This module retrieves function call relationships (callees) from Git repositories, supporting multi-layer retrieval.

## Files

- `code_retrieval.py`: Core code retrieval logic
- `process_callee.py`: Main entry point

## Usage

### 1. Preparation

Ensure that the required project repositories have been cloned:

```bash
# Run the repository cloning script (from project root)
python utils/clone_all_primevul_repos.py
```

> Note: Repository path needs to be configured in `process_callee.py` with the `repo_base_path` variable

### 2. Run Code Retrieval

```bash
# Run from project root
python phase1/process_callee.py
```

### 3. Configuration

You can modify the following parameters in `process_callee.py`:

```python
# Maximum retrieval layers
n_layer = 6

# Input file (JSONL or JSON format)
inpath = "path/to/your/input.jsonl"

# Repository base path
repo_base_path = "path/to/your/repos"
```

> Note: Please modify these configurations according to your actual data paths

## Data Format

### Input Format (JSONL)

Each line is a JSON object with the following fields:

```json
{
  "idx": 0,
  "target": 1,
  "project": "openssl",
  "commit_id": "ca989269a2876bae79393bd54c3e72d49975fc75",
  "func": "long ssl_get_algorithm2(SSL *s) { ... }"
}
```

### Output Format (JSONL)

```json
{
  "idx": 0,
  "target": 1,
  "project": "openssl",
  "commit_id": "ca989269a2876bae79393bd54c3e72d49975fc75",
  "func": "long ssl_get_algorithm2(SSL *s) { ... }",
  "func_name": "ssl_get_algorithm2",
  "callee": [
    {
      "layer": 1,
      "func_name": "TLS1_get_version",
      "func_str": "...",
      "caller": "ssl_get_algorithm2"
    }
  ]
}
```

## Workflow

1. **Stage 1: Sample Parsing**
   - Read input file (supports JSON and JSONL formats)
   - Extract function names

2. **Stage 2: Callee Retrieval**
   - Iterate through each sample
   - Automatically match repository by project name
   - Checkout corresponding commit
   - Use cscope and ctags to retrieve call relationships
   - Recursively retrieve callees up to specified layers

## Statistics

The following statistics are displayed during execution:

- 📈 Retrieval success/failure statistics
- ⚡ Performance optimization statistics (Git checkout count, index reuse rate, etc.)

## Notes

1. **Repository Completeness**: Ensure all project repositories are properly cloned
2. **Runtime**: May take a long time depending on the number of samples (recommended to run in background with nohup)
3. **Dependencies**: Requires system installation of `cscope` and `ctags`

## Dependency Installation

```bash
# Ubuntu/Debian
sudo apt-get install cscope exuberant-ctags

# CentOS/RHEL
sudo yum install cscope ctags
```

## Example Output

```
Starting code retrieval...
Input file: path/to/input.jsonl
Maximum retrieval layers: 6

stage1: Sample parsing complete ===============
Total parsed 187968 samples

stage2: Starting callee retrieval ===============
[Project1] Starting to process 100 samples
[Project1] ✅ Processing complete
[Project2] Starting to process 200 samples
[Project2] ✅ Processing complete
...

⚡ Performance optimization statistics:
  Git checkout: 5000 times
  Index reuse: 45000 times
  Reuse rate: 90.0%
```

## FAQ

**Q: Why are some samples skipped?**  
A: There are three main cases:
1. Repository does not exist (need to clone first)
2. Unable to extract function name
3. No callees found (function does not call other functions)

**Q: How to speed up retrieval?**  
A: 
1. Reduce retrieval layers (n_layer)
2. Use multi-process parallel processing
3. Use SSD storage for repositories

**Q: Which programming languages are supported?**  
A: Currently mainly supports C/C++ language projects
