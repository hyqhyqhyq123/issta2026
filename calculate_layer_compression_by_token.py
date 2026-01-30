#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
from collections import defaultdict

try:
    import tiktoken
    # Use cl100k_base encoding (encoding used by GPT-3.5/GPT-4)
    _tokenizer = tiktoken.get_encoding("cl100k_base")
    USE_TIKTOKEN = True
except ImportError:
    USE_TIKTOKEN = False
    import re

def count_tokens(text):
    """
    Calculate token count of text
    Prefer tiktoken library (more accurate), fall back to simple regex method if unavailable
    """
    if not text or not text.strip():
        return 0
    
    if USE_TIKTOKEN:
        # Use tiktoken for token counting (more accurate)
        try:
            return len(_tokenizer.encode(text))
        except Exception:
            # If encoding fails, fall back to simple method
            pass
    
    # Fallback method: simple token counting
    text = text.strip()
    tokens = re.findall(r'\b\w+\b|[^\w\s]', text)
    return len(tokens)

def get_total_tokens_by_layer(entry, layer, use_original_lines=False, original_entry=None):
    """
    Calculate total token count for specified layer
    
    Args:
        entry: Data entry (original data or sliced data)
        layer: Target layer
        use_original_lines: If True, prefer original_lines/sliced_lines fields
                           If False, use actual token count of func_str
        original_entry: Original data entry (for matching function names and layers)
    """
    total_tokens = 0
    func = entry.get('func', '')
    total_tokens += count_tokens(func)
    
    # If original data provided, use layer information from original data to match functions
    if original_entry is not None:
        # Build set of function names with layer <= target_layer in original data
        original_callees_by_name = {}
        for callee in original_entry.get('callee', []):
            callee_layer = callee.get('layer')
            func_name = callee.get('func_name')
            if callee_layer is not None and callee_layer <= layer and func_name:
                original_callees_by_name[func_name] = callee_layer
        
        # Only calculate functions with layer <= target_layer in original data
        callee_list = entry.get('callee', [])
        for callee in callee_list:
            func_name = callee.get('func_name')
            if func_name in original_callees_by_name:
                if use_original_lines:
                    # For sliced data, need to calculate token count of func_str
                    # Because sliced_lines is line count, not token count
                    func_str = callee.get('func_str', '')
                    total_tokens += count_tokens(func_str)
                else:
                    # Use actual token count of func_str (original data)
                    func_str = callee.get('func_str', '')
                    total_tokens += count_tokens(func_str)
    else:
        # If original data not provided, use layer information in entry
        callee_list = entry.get('callee', [])
        for callee in callee_list:
            callee_layer = callee.get('layer')
            if callee_layer is not None and callee_layer <= layer:
                func_str = callee.get('func_str', '')
                total_tokens += count_tokens(func_str)
    
    return total_tokens

def process_dataset(dataset, slicer_type):
    """Process single dataset and slicing method"""
    
    if dataset == 'devign':
        if slicer_type == 'sysevr':
            compressed_file = ''
        else:
            compressed_file = ''
        original_file = ''
        label_file = ''
    elif dataset == 'primevul':
        if slicer_type == 'sysevr':
            compressed_file = ''
        else:
            compressed_file = ''
        original_file = ''
        label_file = ''
    else:
        return None
    
    labeled_data = {}
    try:
        with open(label_file, 'r', encoding='utf-8') as f:
            first_char = f.read(1)
            f.seek(0)
            
            if first_char == '[':
                data = json.load(f)
                for item in data:
                    if 'idx' in item:
                        labeled_data[item['idx']] = item
            else:
                for line in f:
                    if line.strip():
                        item = json.loads(line)
                        if 'idx' in item:
                            labeled_data[item['idx']] = item
    except FileNotFoundError:
        return None
    
    original_data = {}
    try:
        with open(original_file, 'r', encoding='utf-8') as f:
            for line in f:
                if not line.strip():
                    continue
                entry = json.loads(line)
                idx = entry.get('idx')
                if idx is not None:
                    original_data[idx] = entry
    except FileNotFoundError:
        return None
    
    compressed_data_all = {}
    try:
        with open(compressed_file, 'r', encoding='utf-8') as f:
            for line in f:
                if not line.strip():
                    continue
                entry = json.loads(line)
                idx = entry.get('idx')
                if idx is not None:
                    compressed_data_all[idx] = entry
    except FileNotFoundError:
        return None
    
    missing_in_labeled = set(compressed_data_all.keys()) - set(labeled_data.keys())
    
    matched_indices = set(compressed_data_all.keys()) & set(labeled_data.keys()) & set(original_data.keys())
    
    max_layer = 0
    try:
        with open(compressed_file, 'r', encoding='utf-8') as f:
            for line in f:
                if not line.strip():
                    continue
                entry = json.loads(line)
                callee_list = entry.get('callee', [])
                for callee in callee_list:
                    layer = callee.get('layer')
                    if layer is not None:
                        max_layer = max(max_layer, layer)
    except:
        pass
    
    if max_layer == 0:
        max_layer = 0
    
    layer_ratios = defaultdict(list)
    layer_ratio_samples = defaultdict(list)
    
    with open(compressed_file, 'r', encoding='utf-8') as f:
        for line in f:
            if not line.strip():
                continue
            entry = json.loads(line)
            idx = entry.get('idx')
            if idx is None or idx not in labeled_data or idx not in original_data:
                continue
            
            original_entry = original_data[idx]
            layers_to_calculate = [0] if max_layer == 0 else list(range(0, max_layer + 1))
            
            for layer in layers_to_calculate:
                # Original data: use actual token count of func_str
                original_tokens = get_total_tokens_by_layer(original_entry, layer, use_original_lines=False)
                # Sliced data: use actual token count of func_str
                compressed_tokens = get_total_tokens_by_layer(entry, layer, use_original_lines=True, original_entry=original_entry)
                
                if original_tokens > 0:
                    ratio = 1 - (compressed_tokens / original_tokens)
                    layer_ratios[layer].append(ratio)
                    layer_ratio_samples[layer].append((idx, layer, ratio, original_tokens, compressed_tokens))
    
    all_ratios = []
    all_samples = []
    for layer in sorted(layer_ratio_samples.keys()):
        for sample in layer_ratio_samples[layer]:
            all_ratios.append(sample[2])
            all_samples.append(sample)
    
    if all_ratios:
        overall_avg = sum(all_ratios) / len(all_ratios)
        overall_min = min(all_ratios)
        overall_max = max(all_ratios)
        sorted_all = sorted(all_ratios)
        overall_median = sorted_all[len(sorted_all) // 2]
    else:
        overall_avg = overall_min = overall_max = overall_median = 0
    
    return {
        'dataset': dataset,
        'slicer_type': slicer_type,
        'layer_ratios': dict(layer_ratios),
        'overall_stats': {
            'avg': overall_avg if all_ratios else 0,
            'min': overall_min if all_ratios else 0,
            'max': overall_max if all_ratios else 0,
            'median': overall_median if all_ratios else 0,
            'total_samples': len(all_ratios)
        }
    }

def main():
    """Main function: one-click execution of all combinations"""
    
    datasets = ['devign', 'primevul']
    slicer_types = ['original']
    
    results = []
    
    for dataset in datasets:
        for slicer_type in slicer_types:
            result = process_dataset(dataset, slicer_type)
            if result:
                results.append(result)

if __name__ == '__main__':
    main()


