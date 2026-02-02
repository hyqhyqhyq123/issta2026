## Project Overview

This project is a **research-oriented** vulnerability detection/risk localization pipeline organized by phases:

- **Phase 1 (`phase1/`)**: Function-level code retrieval (callee expansion) from sample-corresponding code repositories to build more complete code context.
- **Phase 2 (`phase2/`)**:
  - **Risk Scoring/Candidate Line Generation (`phase2/score_calculate/`)**: Includes similarity scoring, LLM line-by-line risk assessment, and report/candidate line post-processing scripts.
  - **Program Slicing (`phase2/risk_line_slicer.py`)**: Perform forward/backward slicing starting from risk lines, output compressed code snippets.
  - **Data Preprocessing (`phase2/data_processing/`)**: Convert JSONL samples to C file directories organized by samples.
- **Phase 3 (`phase3/`)**:
  - **Dataset Generation (`phase3/generate_dataset.py`)**: Merge program slicing results and code audit reports, concatenate code pieces to generate training data
  - **Model Training/Evaluation (`phase3/run.py`)**: Binary classification vulnerability detection training and evaluation based on UniXcoder

> Note: This repository is primarily research code and experimental workflow scripts, not intended as a "production CLI"; you need to make minor modifications to configuration items in each script according to your data paths.

---

## Directory Structure (Key Files)

- `requirements.txt`: Python dependencies (with fixed versions)
- `common.py`: Common utility functions (retry, truncation, JSON extraction, etc.)
- `phase1/code_retrieval.py`: Phase 1 core retrieval logic
- `phase1/process_callee.py`: Phase 1 entry script
- `phase2/score_calculate/`: Phase 2 risk line generation scripts
  - `phase2/score_calculate/phase2_config.py`: LLM risk assessment configuration (model name, concurrency, input/output paths, etc.)
  - `phase2/score_calculate/llm_score_calculator.py`: Call LLM to generate risk lines
  - `phase2/score_calculate/similarity_score_calculator.py`: Vector similarity scoring 
  - `phase2/score_calculate/get_high_candidate_line.py`: Generate final risk lines based on candidate line scores/thresholds 
- `phase2/risk_line_slicer.py`: Program slicing starting from risk lines
- `phase3/generate_dataset.py`: Merge slicing and summary fields to generate training data
- `phase3/run.py`: Training/evaluation/testing/single prediction entry

---

## Environment and Dependencies (Reproducible)

### Python Environment

Recommended to use a virtual environment (works on Windows/Linux):

```bash
python -m venv .venv
```

- Windows (PowerShell):

```bash
.venv\Scripts\Activate.ps1
python -m pip install -U pip
pip install -r requirements.txt
```

- Linux/macOS (bash/zsh):

```bash
source .venv/bin/activate
python -m pip install -U pip
pip install -r requirements.txt
```

### Additional System Dependencies

- **Phase 1**: Code retrieval may depend on system tools ( `cscope` / `ctags`), whether required depends on your retrieval implementation and dataset source.
- **Phase 2**: Program slicing requires **Joern** for CPG (Code Property Graph) generation. See `phase2/README.md` for installation instructions.

---

## Data Format Conventions (Core Fields)

Most scripts use **JSONL** as input/output (one JSON object per line). Common fields:

- `idx`: Sample index (integer)
- `target`: Label (0/1)
- `func_name`: Target function name
- `func`: Target function code string
- `callee`: Called function list (usually contains `layer`, `func_name`, `func_str`, `caller`, etc.)
- `summary`: Summary used in Phase 2 (may be string or dict, contains `high_level_summary` field)

**Note**: In Phase 3 training data, the `func` field already contains concatenated code (base function + callee functions + audit summary), and no longer separately contains `callee` and `summary` fields.

Different datasets/phases may have field additions or deletions, refer to the reading logic in the corresponding scripts.

---

## Typical Experimental Workflow (Phase 1 to Phase 3)

Below is a common execution order "by phase". **You need to configure input/output paths in the corresponding scripts first** (e.g., JSONL paths, repository paths, output directories, etc.).

### Phase 1: Callee Retrieval (Generate More Complete Context)

Entry:

```bash
python phase1/process_callee.py
```

Output is usually JSONL with `callee` field (specific path determined by variables in the script).

### Phase 2: Risk Line (risk lines) Generation

1) Vector similarity scoring/candidate line scores:

```bash
python phase2/score_calculate/similarity_score_calculator.py
```

2) LLM line-by-line risk assessment (generate risk lines):

After configuring `OPENAI_API_KEY`, `OPENAI_BASE_URL`, input/output paths, etc. in `phase2/score_calculate/phase2_config.py`, run:

```bash
python phase2/score_calculate/llm_score_calculator.py
```

3)  Candidate line post-processing:

```bash
python phase2/score_calculate/get_high_candidate_line.py
```

### Phase 2: Program Slicing (Starting from risk lines)

Slicing script:

```bash
python phase2/risk_line_slicer.py
```

This script typically requires you to provide:

- Parsed CPG/intermediate product directory (e.g., organized by `idx/`)
- Original sample C file directory (also organized by `idx/`)
- Risk lines input file (JSONL)

> For specific parameters/paths, refer to the entry function/default values in `phase2/risk_line_slicer.py`.

### Phase 3: Generate Training Data + Training/Evaluation

1) Generate Phase 3 dataset (merge slicing results and summary, concatenate code pieces):

```bash
python phase3/generate_dataset.py \
    --sliced path/to/sliced_from_risk_lines.jsonl \
    --report path/to/summary.jsonl \
    --output path/to/train_dataset.jsonl
```

2) Data splitting :

```bash
python data_split_811.py \
    --input path/to/train_dataset.jsonl \
    --output_dir path/to/output/
```

3) Training/Evaluation/Testing:

```bash
# Set dataset paths
dataset="primevul"
DATA_DIR="path/to/data/${dataset}/phase3_input/${dataset}"
TRAIN_FILE="${DATA_DIR}/train_dataset.jsonl"
EVAL_FILE="${DATA_DIR}/val_dataset.jsonl"
TEST_FILE="${DATA_DIR}/test_dataset.jsonl"

# Run training
python phase3/run.py \
    --do_train \
    --do_eval \
    --do_test \
    --dataset_type=${dataset} \
    --dataset_name=${dataset} \
    --model_name_or_path=microsoft/unixcoder-base-nine \
    --train_data_file="$TRAIN_FILE" \
    --eval_data_file="$EVAL_FILE" \
    --test_data_file="$TEST_FILE" \
    --output_dir="./saved_models/${dataset}" \
    --max_source_length=512 \
    --train_batch_size=32 \
    --eval_batch_size=32 \
    --learning_rate=2e-5 \
    --num_train_epochs=15 \
    --patience=5 \
    --seed=42 \
    --save_metric=f1
```

> For detailed parameter descriptions and configuration, refer to `phase3/README.md`

---

## Reproducibility Recommendations 

To ensure reproducibility, it is recommended to record the following information for each experiment (can be written to experiment logs or a separate `experiments/` record file):

- **Code Version**: Git commit id (if using version control)
- **Random Seed**: Phase 3 `--seed`
- **Hardware Information**: GPU model, CUDA/Driver version
- **Dependency Versions**: Use this repository's `requirements.txt`
- **Complete Commands**: Actual running commands and parameters for training/evaluation/slicing scripts
- **Artifact Paths**: Model checkpoints, logs, generated dataset files, etc.

---

## FAQ

- **Q: Which script should I start with?**  
  A: If you already have context data with `callee`, you can start from Phase 2; otherwise, it is recommended to run in the order Phase 1 → Phase 2 → Phase 3.

---

## Disclaimer

This project is for research experiments and reproduction, and does not guarantee out-of-the-box use for any dataset/repository; please make necessary configurations according to your data paths and environment.


