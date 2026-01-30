#!/usr/bin/env python3
import json
from pathlib import Path
import phase2_config 
# Input files
name=phase2_config.MODEL_NAME
llm_risk_file = Path("")
similarity_risk_file = Path("")
c_files_dir = Path("")
output_file = Path("")

# Load similarity scores (build index)
similarity_map = {}
with similarity_risk_file.open() as f:
    for line in f:
        data = json.loads(line)
        idx = data['idx']
        line_scores = data['line_scores']
        # Convert string keys to integers
        similarity_map[idx] = {int(k): v for k, v in line_scores.items()}

# Helper function to read C file content
def get_line_content(idx: int, line_num: int) -> str:
    c_file = c_files_dir / f"{idx}.c"
    if not c_file.exists():
        return ""
    try:
        with c_file.open() as f:
            lines = f.readlines()
            if 0 < line_num <= len(lines):
                return lines[line_num - 1].strip()
    except:
        pass
    return ""

# Process risk lines
results = []
with llm_risk_file.open() as f:
    for line in f:
        data = json.loads(line)
        idx = data['idx']
        func_name = data['func_name']
        risk_lines = data['risk_lines']
        
        # Filter risk lines with line_number > 0
        valid_risk_lines = [r for r in risk_lines if r['line_number'] > 0]
        
        # Get corresponding similarity scores
        sim_scores = similarity_map.get(idx, {})
        # Collect candidate lines (deduplicate)
        candidate_lines = {}  # line_num -> {score, content, source}
        
        # 1. Process LLM risk lines
        for risk in valid_risk_lines:
            line_num = risk['line_number']
            llm_score = 0.5
            sim_score = sim_scores.get(line_num, 0.0)
            combined_score = llm_score + sim_score*0.5
            candidate_lines[line_num] = {
                'final_score': combined_score,
                'line_content': risk['line_content'],
            }
        
        for line_num, sim_score in sim_scores.items():
            if sim_score and line_num not in candidate_lines:
                line_content = get_line_content(idx, line_num)
                if line_content and len(line_content) > 2:
                    candidate_lines[line_num] = {
                        'final_score': sim_score,
                        'line_content': line_content,
                    }
        
        # Convert to list and sort by line number
        line_details = [
            {
                'line_number': line_num,
                'final_score': info['final_score'],
                'line_content': info['line_content'],
            }
            for line_num, info in sorted(candidate_lines.items())
        ]
        results.append({
            'idx': idx,
            'target': data['target'],
            'func_name': func_name,
            'line_details': line_details
        })

results.sort(key=lambda x: x['idx'])

with output_file.open('w') as f:
    for r in results:
        f.write(json.dumps(r, ensure_ascii=False) + '\n')

