import json
import logging
from pathlib import Path


INPUT = Path("")
OUTPUT = Path("")
TARGET_KEY = "target"


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")

    if not INPUT.exists():
        logging.error("Input file does not exist: %s", INPUT)
        raise SystemExit(1)

    # Prefer reading as JSON array; fall back to JSONL line-by-line reading
    records = []
    try:
        data = json.loads(INPUT.read_text(encoding="utf-8"))
        if isinstance(data, list):
            records = [x for x in data if isinstance(x, dict)]
        else:
            logging.warning("Root node is not an array, trying to read as JSONL")
            raise ValueError("not array")
    except Exception:
        with INPUT.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        records.append(obj)
                except json.JSONDecodeError:
                    continue

    kept = [r for r in records if isinstance(r, dict) and r.get(TARGET_KEY) == 1]
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT.open("w", encoding="utf-8") as w:
        for r in kept:
            w.write(json.dumps(r, ensure_ascii=False) + "\n")

    logging.info("Complete: Read %d records, kept %d records, output -> %s", len(records), len(kept), OUTPUT)


if __name__ == "__main__":
    main()


