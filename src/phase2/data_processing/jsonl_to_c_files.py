#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Convert devign_callee.jsonl to C file directory structure
Each sample has one directory containing main function and called function .c files
"""

import json
import os
from pathlib import Path
from tqdm import tqdm


def sanitize_filename(name: str) -> str:
    """Clean filename, remove illegal characters"""
    # Replace illegal characters
    illegal_chars = '<>:"/\\|?*'
    for char in illegal_chars:
        name = name.replace(char, '_')
    return name


def create_c_file(output_dir: Path, func_name: str, func_code: str):
    """Create C file"""
    # Clean function name
    safe_func_name = sanitize_filename(func_name)
    c_file = output_dir / f"{safe_func_name}.c"
    
    with open(c_file, 'w', encoding='utf-8') as f:
        f.write(func_code)
    
    return c_file


def process_sample(sample: dict, output_base_dir: Path):
    """Process single sample"""
    idx = sample['idx']
    func_name = sample['func_name']
    func_code = sample['func']
    callees = sample.get('callee', [])
    
    # Create sample directory: idx_target
    sample_dir = output_base_dir / f"{idx}"
    sample_dir.mkdir(parents=True, exist_ok=True)
    
    # 1. Create main function file
    main_file = create_c_file(sample_dir, func_name, func_code)
    
    # 2. Create called function files
    callee_files = []
    for callee in callees:
        callee_name = callee['func_name']
        callee_code = callee['func_str']
        callee_file = create_c_file(sample_dir, callee_name, callee_code)
        callee_files.append(callee_file.name)
    
    # 3. Create metadata file
    metadata = {
        'idx': idx,
        'project': sample.get('project', ''),
        'commit_id': sample.get('commit_id', ''),
        'func_name': func_name,
        'main_file': f"{sanitize_filename(func_name)}.c",
        'callee_files': callee_files,
        'callee_count': len(callees)
    }
    
    with open(sample_dir / 'metadata.json', 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)
    
    return sample_dir


def convert_jsonl_to_c_files(jsonl_file: str, output_dir: str, limit: int = None):
    """
    Convert JSONL file to C file directory structure
    
    Args:
        jsonl_file: Input JSONL file path
        output_dir: Output directory
        limit: Limit number of samples to process (None = all)
    """
    output_base = Path(output_dir)
    output_base.mkdir(parents=True, exist_ok=True)
    
    samples = []
    with open(jsonl_file, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                try:
                    sample = json.loads(line)
                    samples.append(sample)
                    if limit and len(samples) >= limit:
                        break
                except json.JSONDecodeError as e:
                    continue
    
    created_dirs = []
    stats = {
        'total': len(samples),
        'success': 0,
        'failed': 0,
        'total_callees': 0
    }
    
    for sample in tqdm(samples, desc="Converting samples"):
        try:
            sample_dir = process_sample(sample, output_base)
            created_dirs.append(sample_dir)
            stats['success'] += 1
            stats['total_callees'] += len(sample.get('callee', []))
        except Exception as e:
            stats['failed'] += 1
    
    return created_dirs, stats


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Convert JSONL to C file directory')
    parser.add_argument('--input',
                       default='',
                       help='Input JSONL file')
    parser.add_argument('--output',
                       default='',
                       help='Output directory')
    parser.add_argument('--limit',
                       type=int,
                       default=5000000000,
                       help='Limit number of samples to process (for testing)')
    
    args = parser.parse_args()
    
    created_dirs, stats = convert_jsonl_to_c_files(
        args.input,
        args.output,
        args.limit
    )
    

if __name__ == '__main__':
    main()

