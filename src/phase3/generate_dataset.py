#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generate training dataset: merge from sliced_from_risk_lines.jsonl and summary.jsonl
"""

import json
from pathlib import Path


def clean_callee(callee_list: list) -> list:
    """
    Clean callee list, remove unnecessary fields
    """
    cleaned = []
    for callee in callee_list:
        cleaned_callee = {
            'layer': callee.get('layer'),
            'func_name': callee.get('func_name'),
            'func_str': callee.get('func_str'),
            'caller': callee.get('caller')
        }
        cleaned.append(cleaned_callee)
    return cleaned


def generate_dataset(
    sliced_file: str,
    report_file: str,
    output_file: str
):
    """
    Merge sliced data and summary data, concatenate code pieces
    """
    # Read summary data, build idx -> summary mapping
    summaries = {}
    with open(report_file, 'r', encoding='utf-8') as f:
        for line in f:
            if not line.strip():
                continue
            data = json.loads(line)
            summaries[data['idx']] = data['summary']
    
    output_data = []
    matched_count = 0
    
    with open(sliced_file, 'r', encoding='utf-8') as f:
        for line in f:
            if not line.strip():
                continue
            
            data = json.loads(line)
            idx = data['idx']
            
            if idx not in summaries:
                continue
            
            base_func = data.get('func', '')
            
            high_level_summary = ''
            summary = summaries[idx]
            if isinstance(summary, dict):
                high_level_summary = summary.get('high_level_summary', '')
            
            callee_funcs = []
            if isinstance(data.get('callee'), list):
                for callee_item in data['callee']:
                    if isinstance(callee_item, dict):
                        layer = callee_item.get('layer')
                        if layer is not None and layer > 3:
                            continue
                        func_str = callee_item.get('func_str', '')
                        if func_str:
                            callee_funcs.append(func_str)
            
            callee_concat = "\n".join(callee_funcs)
            
            pieces = [base_func, callee_concat, high_level_summary]
            code = "\n".join([p for p in pieces if isinstance(p, str) and len(p) > 0])
            
            new_data = {
                'idx': idx,
                'target': data['target'],
                'func_name': data.get('func_name', ''),
                'func': code
            }
            
            output_data.append(new_data)
            matched_count += 1
    
    with open(output_file, 'w', encoding='utf-8') as f:
        for item in output_data:
            f.write(json.dumps(item, ensure_ascii=False) + '\n')


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate training dataset')
    parser.add_argument('--sliced', 
                       default='',
                       help='Sliced data file path')
    parser.add_argument('--report',
                       default='',
                       help='Report file path')
    parser.add_argument('--output',
                       default='',
                       help='Output file path')
    
    args = parser.parse_args()
    
    generate_dataset(args.sliced, args.report, args.output)

