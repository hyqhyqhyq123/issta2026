#!/usr/bin/env python3
import json
import re
import sys
import time
from pathlib import Path
from typing import Dict, List
import os
from openai import OpenAI
os.environ.pop('http_proxy', None)
os.environ.pop('https_proxy', None)
os.environ.pop('HTTP_PROXY', None)
os.environ.pop('HTTPS_PROXY', None)
os.environ.pop('all_proxy', None)
os.environ.pop('ALL_PROXY', None)

# Disable proxy to ensure access to internal vLLM service
for proxy_var in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
    os.environ.pop(proxy_var, None)

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))
import phase2_config

# Import unified utility functions
sys.path.insert(0, str(Path(__file__).parent.parent))

CANDIDATE_FILE = Path("")
C_WITH_COMMENT_DIR = Path("")
FINAL_FILE = Path("")

_client = OpenAI(api_key=phase2_config.OPENAI_API_KEY, base_url=phase2_config.OPENAI_BASE_URL)



def load_processed_indices(output_file: Path) -> set:
    """Load set of processed idx"""
    processed_indices = set()
    
    if not output_file.exists():
        return processed_indices
    
    try:
        with output_file.open('r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    data = json.loads(line)
                    if 'idx' in data:
                        processed_indices.add(data['idx'])
    except Exception as e:
        pass
    
    return processed_indices


def main():
    HI_TH = 0.5
    
    processed_indices = load_processed_indices(FINAL_FILE)
    
    # Statistics variables
    total_samples = 0
    total_risk_lines = 0
    skipped_count = 0
    processed_count = 0  # Total processing count (including skipped)
    
    # Real-time write mode: open output file
    with FINAL_FILE.open("a", encoding="utf-8") as output_file, \
         CANDIDATE_FILE.open() as f:
        for line in f:
            processed_count += 1
            if not line.strip():
                continue
            entry = json.loads(line)
            idx = entry["idx"]
            
            # Skip already processed samples
            if idx in processed_indices:
                skipped_count += 1
                continue
            
            func_name = entry["func_name"]
            details = entry.get("line_details", [])

            kept = []
            # Directly keep lines > HI_TH
            for d in details:
                if d.get("final_score", 0.0) > HI_TH:
                    kept.append(d["line_content"])

            if (not kept or len(kept) == 1) and details:
                if len(details) == 1:
                    # Only one line of code left, keep directly
                    if not kept:
                        kept = [details[0]["line_content"]]
                else:
                    # Take two highest-scoring lines not yet kept
                    already = set(kept)
                    # Get all unkept lines, sort by score descending
                    candidates = [d for d in details if d["line_content"] not in already]
                    candidates = sorted(candidates, key=lambda d: d.get("final_score", 0.0), reverse=True)
                    to_add = []
                    if len(kept) == 1:
                        # Only add one line, ensure no duplicates
                        if candidates:
                            to_add.append(candidates[0]["line_content"])
                    else:
                        # All empty, add two lines
                        to_add = [d["line_content"] for d in candidates[:2]]
                    kept.extend(to_add)
            
            # Real-time write results
            if kept:
                result = {
                    "idx": idx,
                    "target": entry['target'],
                    "func_name": func_name,
                    "final_risk_lines": kept,
                }
                output_file.write(json.dumps(result, ensure_ascii=False) + "\n")
                output_file.flush()  # Immediately flush to disk
                
                total_samples += 1
                total_risk_lines += len(kept)

if __name__ == "__main__":
    main()
