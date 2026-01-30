# Phase 3: Model Training and Evaluation

## Overview

Phase 3 uses the UniXcoder model for binary classification vulnerability detection on sliced code data. Includes:
1. **Dataset Generation**: Merge program slicing results and code audit reports
2. **Model Training**: Fine-tuning based on UniXcoder
3. **Model Evaluation**: Calculate various evaluation metrics (accuracy, F1, F2, MCC, G-mean, specificity, FPR@95%TPR, etc.)
4. **Model Prediction**: Predict single samples

## Directory Structure

```
phase3/
├── generate_dataset.py  # Generate training dataset (merge slicing and reports)
├── model.py            # UniXcoder model definition
├── run.py              # Training/evaluation/prediction entry script
└── README.md           # This file
```

## Workflow

### Step 1: Generate Training Dataset

Merge Phase 2 program slicing results and code audit reports to generate the final training dataset. The script automatically concatenates code pieces:
- Base function code (`func` field)
- Callee function code (`func_str` from `callee` with `layer <= 3`)
- Code audit summary (`high_level_summary` from `summary`)

```bash
python phase3/generate_dataset.py \
    --sliced path/to/sliced_from_risk_lines.jsonl \
    --report path/to/summary.jsonl \
    --output path/to/train_dataset.jsonl
```

**Parameters**:
- `--sliced`: Program slicing result file (from `phase2/risk_line_slicer.py`)
- `--report`: Code audit report file (from `phase2/score_calculate/get_report.py`)
- `--output`: Output dataset file path

**Output Format** (JSONL):
```json
{
  "idx": 0,
  "target": 1,
  "func_name": "function_name",
  "func": "base_func_code\ncallee_func_code_1\ncallee_func_code_2\nhigh_level_summary"
}
```

**Concatenation Logic**:
- Concatenate in order: `[base_func, callee_concat, high_level_summary]`
- Only include callee function code with `layer <= 3`
- Automatically filter empty strings, join with newlines
- Output no longer contains `callee` and `summary` fields

### Step 2: Data Splitting

Split training/validation/test sets using `data_split_811.py` in the root directory:

```bash
python data_split_811.py \
    --input path/to/train_dataset.jsonl \
    --output_dir path/to/output/
```

Default split ratio: Training set 80%, Validation set 10%, Test set 10%

### Step 3: Model Training

```bash
# Set dataset paths
dataset="primevul"
DATA_DIR="path/to/data/${dataset}/phase3_input/${dataset}"
TRAIN_FILE="${DATA_DIR}/train_dataset.jsonl"
EVAL_FILE="${DATA_DIR}/val_dataset.jsonl"
TEST_FILE="${DATA_DIR}/test_dataset.jsonl"

# Set model output directory
OUTPUT_DIR="./saved_models/${dataset}"
mkdir -p "$OUTPUT_DIR"

# Run training and evaluation
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
    --output_dir="$OUTPUT_DIR" \
    --max_source_length=512 \
    --train_batch_size=32 \
    --eval_batch_size=32 \
    --learning_rate=2e-5 \
    --weight_decay=0.01 \
    --num_train_epochs=15 \
    --patience=5 \
    --seed=42 \
    --save_metric=f1 \
    2>&1 | tee train_${dataset}.log
```

**Main Parameters**:
- `--do_train`: Execute training
- `--do_eval`: Execute validation
- `--do_test`: Execute testing
- `--dataset_type`: Dataset type (for data loading logic)
- `--dataset_name`: Dataset name
- `--train_data_file`: Training set file path
- `--eval_data_file`: Validation set file path
- `--test_data_file`: Test set file path
- `--model_name_or_path`: Pre-trained model path (e.g., `microsoft/unixcoder-base-nine`)
- `--output_dir`: Model and log output directory
- `--max_source_length`: Maximum code length (number of tokens, default 512)
- `--train_batch_size`: Training batch size (default 32)
- `--eval_batch_size`: Evaluation batch size (default 32)
- `--learning_rate`: Learning rate (default 2e-5)
- `--weight_decay`: Weight decay (default 0.01)
- `--num_train_epochs`: Number of training epochs (default 15)
- `--patience`: Early stopping patience (default 5)
- `--seed`: Random seed (for reproducibility, default 42)
- `--save_metric`: Metric for saving best model (default f1)

### Step 4: Model Evaluation

If `--do_eval` and `--do_test` were used during training, evaluation and testing are automatically completed during training. If you need to evaluate separately:

```bash
python phase3/run.py \
    --do_eval \
    --eval_data_file path/to/test.jsonl \
    --model_name_or_path path/to/saved_models/dataset/checkpoint-best \
    --max_source_length 512 \
    --eval_batch_size 32
```

**Evaluation Metrics**:
- **Accuracy**: Accuracy
- **Precision**: Precision
- **Recall**: Recall
- **F1 Score**: F1 score
- **F2 Score**: F2 score (emphasizes recall more)
- **MCC**: Matthews correlation coefficient
- **G-mean**: Geometric mean (√(Sensitivity × Specificity))
- **Specificity**: Specificity (true negative rate)
- **FPR@95%TPR**: False positive rate at 95% true positive rate

### Step 5: Model Testing

If `--do_test` was used during training, testing is automatically completed during training. If you need to test separately:

```bash
python phase3/run.py \
    --do_test \
    --test_data_file path/to/test.jsonl \
    --model_name_or_path path/to/saved_models/dataset/checkpoint-best \
    --max_source_length 512 \
    --eval_batch_size 32
```

### Step 6: Single Sample Prediction 

```bash
python phase3/run.py \
    --do_predict \
    --predict_data_file path/to/predict.jsonl \
    --model_name_or_path path/to/saved_models/dataset/checkpoint-best \
    --max_source_length 512 \
    --eval_batch_size 32 \
    --predict_output_file path/to/predictions.jsonl
```

## Model Architecture

### UniXcoderForVulDetection

Vulnerability detection model based on UniXcoder:

```python
class UniXcoderForVulDetection(nn.Module):
    - unixcoder: UniXcoder encoder (based on RoBERTa)
    - dropout: Dropout layer (prevents overfitting)
    - classifier: Binary classification linear layer
```

**Input Format**:
```
[CLS] <encoder-only> [SEP] code [SEP]
```

**Output**:
- Binary classification logits (0: non-vulnerable, 1: vulnerable)
- Prediction probabilities

## Data Format

### Training/Evaluation Data Format (JSONL)

```json
{
  "idx": 0,
  "target": 1,
  "func_name": "function_name",
  "func": "base_func_code\ncallee_func_code_1\ncallee_func_code_2\nhigh_level_summary"
}
```

**Field Descriptions**:
- `idx`: Sample index
- `target`: Label (0: non-vulnerable, 1: vulnerable)
- `func_name`: Function name
- `func`: Concatenated code string, containing:
  - Base function code
  - Callee function code (`layer <= 3`)
  - Code audit summary (`high_level_summary`)
  - Code will be tokenized and truncated to `max_source_length`

> Note: The `func` field already contains all necessary code information (base function, callee functions, and audit summary), which is concatenated in `generate_dataset.py`. The model directly uses this field for training.

## Configuration and Parameters

### Common Training Parameters

```bash
# Basic configuration
--model_name_or_path microsoft/unixcoder-base-nine
--max_source_length 512

# Training configuration
--train_batch_size 32
--eval_batch_size 32
--learning_rate 2e-5
--num_train_epochs 15
--weight_decay 0.01

# Early stopping and saving
--patience 5
--save_metric f1

# Other
--seed 42
```

### Data Path Configuration

Data file path structure:
```
data/
└── ${dataset}/
    └── phase3_input/
        └── ${dataset}/
            ├── train_dataset.jsonl
            ├── val_dataset.jsonl
            └── test_dataset.jsonl
```

You can directly specify paths using `--train_data_file`, `--eval_data_file`, `--test_data_file`, or use `--dataset_name` and `--dataset_type` parameters.

## Output Files

The training process generates the following files:

```
saved_models/${dataset}/
├── checkpoint-best/          # Best model checkpoint (selected based on save_metric)
│   ├── config.json
│   ├── pytorch_model.bin
│   └── tokenizer files
├── checkpoint-{step}/         # Other checkpoints
├── train_results.txt          # Training results summary
├── eval_results.txt           # Evaluation results
└── training_args.bin          # Training arguments
```

Training logs are saved to `train_${dataset}.log` file (if using `tee` redirection).

## FAQ

**Q: OOM (out of memory) error during training?**  
A: 
- Reduce `train_batch_size` or `eval_batch_size`
- Reduce `max_source_length`
- Increase `gradient_accumulation_steps` (keep effective batch size unchanged)

**Q: How to select the best checkpoint?**  
A: The script automatically selects the best checkpoint based on F1 score on the validation set, saved in the `checkpoint-best/` directory

**Q: How to continue training?**  
A: Use `--model_name_or_path` to point to an existing checkpoint directory and set a new `--output_dir`

**Q: What do the evaluation metrics mean?**  
A: 
- **FPR@95%TPR**: False positive rate at 95% recall rate, lower is better
- **G-mean**: Metric that balances sensitivity and specificity, suitable for imbalanced datasets
- **MCC**: Metric that comprehensively considers all confusion matrix elements, range [-1, 1], 1 indicates perfect prediction
