import json
import random
from pathlib import Path


INPUT = Path("")
OUT_DIR = Path("")
TRAIN_OUT = OUT_DIR / "train_dataset.jsonl"
VAL_OUT = OUT_DIR / "val_dataset.jsonl"
TEST_OUT = OUT_DIR / "test_dataset.jsonl"
SEED = 42


def _read_records(path: Path):
    # Prefer reading as JSON array; fall back to JSONL line-by-line reading
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return [x for x in data if isinstance(x, dict)]
        # If not array, fall back to JSONL reading
        raise ValueError("root is not array")
    except Exception:
        recs = []
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        recs.append(obj)
                except json.JSONDecodeError:
                    continue
        return recs


def _remove_empty_lines_in_func(records):
    def normalize_func(s: str) -> str:
        return "\n".join([ln for ln in s.splitlines() if ln.strip()])

    for rec in records:
        func = rec.get("func")
        if isinstance(func, str) and func:
            rec["func"] = normalize_func(func)
    return records


def _write_jsonl(records, out_path: Path):
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as w:
        for r in records:
            w.write(json.dumps(r, ensure_ascii=False) + "\n")


def main():
    if not INPUT.exists():
        raise SystemExit(f"Input file does not exist: {INPUT}")

    records = _read_records(INPUT)
    # Preprocessing: remove extra empty lines in func field
    records = _remove_empty_lines_in_func(records)
    if not records:
        raise SystemExit("Input is empty or cannot be parsed as records")

    random.seed(SEED)
    random.shuffle(records)

    n = len(records)
    n_train = int(n * 0.8)
    n_val = int(n * 0.1)
    # Remaining goes to test, ensure total count unchanged
    n_test = n - n_train - n_val

    train = records[:n_train]
    val = records[n_train:n_train + n_val]
    test = records[n_train + n_val:]

    _write_jsonl(train, TRAIN_OUT)
    _write_jsonl(val, VAL_OUT)
    _write_jsonl(test, TEST_OUT)


if __name__ == "__main__":
    main()


