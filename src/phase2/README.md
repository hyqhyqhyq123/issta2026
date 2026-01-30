# Phase 2: Risk Line Generation and Program Slicing

## Overview

Phase 2 consists of two main tasks:
1. **Risk Line Generation**: Identify high-risk lines in code through similarity calculation and LLM evaluation
2. **Program Slicing**: Perform forward/backward slicing starting from risk lines to generate compressed code snippets

## Directory Structure

```
phase2/
├── data_processing/          # Data preprocessing
│   ├── jsonl_to_c_files.py   # Convert JSONL to C file directory structure
│   └── parse_devign_c_files.py  # Parse C files and generate CPG
├── score_calculate/          # Risk line generation scripts
│   ├── phase2_config.py      # Phase 2 configuration (API keys, model parameters, etc.)
│   ├── similarity_score_calculator.py  # Vector similarity scoring
│   ├── llm_score_calculator.py        # LLM line-by-line risk assessment
│   ├── get_candidate_line_scores.py   # Merge similarity and LLM scores
│   ├── get_high_candidate_line.py     # Filter high-confidence candidate lines
│   ├── get_report.py                  # Generate code audit reports
│   ├── match_line_numbers.py          # Match risk lines to actual line numbers
│   ├── vulnerability_database_build.py # Build vulnerability database
│   └── report_config.py               # Report generation configuration
├── risk_line_slicer.py       # Program slicing core logic
└── README.md                 # This file
```

## Workflow

### Step 1: Data Preprocessing

Convert Phase 1 output JSONL data to C file directory structure for subsequent CPG parsing and code analysis.

```bash
python phase2/data_processing/jsonl_to_c_files.py
```

**Input**: JSONL file with `callee` field  
**Output**: C file directory organized by sample index (one directory per sample, containing `.c` files for main function and callee functions)

### Step 2: Generate Code Audit Report

Use LLM to generate global code audit reports, providing context for subsequent risk line identification.

```bash
python phase2/score_calculate/get_report.py
```

**Configuration**: Configure API keys and model parameters in `phase2/score_calculate/report_config.py`

### Step 3: Risk Line Generation

#### 3.1 Similarity Scoring 

Calculate similarity between code snippets and known vulnerabilities based on CodeBERT.

```bash
python phase2/score_calculate/similarity_score_calculator.py
```

**Prerequisites**:
- Need to run `vulnerability_database_build.py` first to build vulnerability database
- Need to prepare known vulnerability codebase

#### 3.2 LLM Line-by-Line Risk Assessment

Use LLM to perform line-by-line risk assessment on code and generate risk line list.

```bash
python phase2/score_calculate/llm_score_calculator.py
```

**Configuration**: Configure in `phase2/score_calculate/phase2_config.py`:
- `OPENAI_API_KEY`: API key
- `OPENAI_BASE_URL`: API base URL
- `MODEL_NAME`: Model name
- `INPUT_JSONL`: Input file path
- `OUTPUT_DIR`: Output directory
- `LAYER`: Number of callee layers to process (default 3)
- `CONCURRENCY_OVERRIDE`: Concurrency (adjust according to API limits)

**Output Format** (JSONL):
```json
{
  "idx": 0,
  "risk_lines": ["memcpy(dst, src, size);", "strcpy(buf, input);"]
}
```

#### 3.3 Merge Scores and Filter Candidate Lines

```bash
# Merge similarity and LLM scores
python phase2/score_calculate/get_candidate_line_scores.py

# Filter high-confidence candidate lines
python phase2/score_calculate/get_high_candidate_line.py
```

### Step 4: Program Slicing

Perform forward/backward program slicing starting from risk lines to generate compressed code snippets.

```bash
python phase2/risk_line_slicer.py
```

**Input Requirements**:
- Parsed CPG directory (organized by `idx/`, each directory contains `metadata.json` and CPG files)
- Original C file directory (organized by `idx/`)
- Risk line input file (JSONL, containing `idx` and `risk_lines` fields)

**Slicing Strategy**:
- **Backward Slicing**: Starting from risk lines, track data dependencies and control dependencies, collect all code that affects risk lines
- **Forward Slicing**: Starting from risk lines, track data flow and control flow, collect all code affected by risk lines
- **Inter-procedural Slicing**: Support data flow and control flow tracking across function boundaries

**Output Format** (JSONL):
```json
{
  "idx": 0,
  "target": 1,
  "func_name": "vulnerable_function",
  "func": "sliced_code_here",
  "callee": [...],
  "sliced_from_risk_lines": true
}
```

## Configuration

### phase2_config.py

Main configuration items:

```python
# API configuration
OPENAI_API_KEY = "your-api-key"
OPENAI_BASE_URL = "https://api.openai.com/v1"
MODEL_NAME = "gpt-4"

# Processing parameters
LAYER = 3                    # Number of callee layers to process
START_IDX = None             # Starting index (None means all)
END_IDX = None               # Ending index (None means all)
CONCURRENCY_OVERRIDE = 50    # Concurrency

# Data paths
INPUT_JSONL = "path/to/input.jsonl"
OUTPUT_DIR = "path/to/output/"
```

### User Tier Configuration

`USER_TIERS` defines limits for different API tiers:
- `Free`: Concurrency 1, RPM 3, TPM 32000
- `Tier1-Tier5`: Gradually increasing concurrency and rate limits

Set `TIER_OVERRIDE` and `CONCURRENCY_OVERRIDE` according to your API tier.

## Data Format

### Input Format (Risk Line Generation)

```json
{
  "idx": 0,
  "target": 1,
  "func_name": "function_name",
  "func": "function_code",
  "callee": [
    {
      "layer": 1,
      "func_name": "callee_func",
      "func_str": "callee_code",
      "caller": "function_name"
    }
  ],
  "summary": {
    "high_level_summary": "code_audit_report"
  }
}
```

### Output Format (Program Slicing)

```json
{
  "idx": 0,
  "target": 1,
  "func_name": "function_name",
  "func": "sliced_code_with_only_risk_related_lines",
  "callee": [...],
  "sliced_from_risk_lines": true
}
```

## Dependencies

### CPG Generation

Program slicing requires CPG (Code Property Graph) files. Usually generated using tools like Joern:

```bash
# Install Joern (example)
# Reference: https://joern.io/docs/installation/

# Generate CPG
joern-parse --language c path/to/c/files
```

### System Dependencies

- Python 3.8+
- Dependencies see project root `requirements.txt`
- Joern (for CPG generation)

## Notes

1. **API Limits**: LLM calls are subject to API rate limits, recommend adjusting concurrency according to your API tier
2. **CPG Files**: Program slicing requires pre-generated CPG files, ensure CPG directory structure is correct
3. **Memory Usage**: Large-scale data slicing may consume significant memory, recommend batch processing
4. **Error Handling**: Scripts automatically skip samples that cannot be processed, check logs for failure reasons

## FAQ

**Q: How to speed up LLM evaluation?**  
A: 
- Increase `CONCURRENCY_OVERRIDE` (note API limits)
- Use higher-tier API accounts
- Reduce number of callee layers processed (`LAYER`)

**Q: What if slicing results are empty?**  
A: 
- Check if CPG files are correctly generated
- Verify risk lines are within target function
- Check if data dependency and control dependency graphs are complete

**Q: How to process only part of the samples?**  
A: Set `START_IDX`, `END_IDX`, or `SAMPLES` parameters in `phase2_config.py`
