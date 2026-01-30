#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
from pathlib import Path


def main():
    """Main function"""
    # File paths
    dataset = 'primevul'
    slicer_type = 'sysevr'  # 'original', 'sysevr' 
    
    if dataset == 'devign':
        label_file = ''
        if slicer_type == 'sysevr':
            sliced_file = ''
        else:
            sliced_file = ''
    elif dataset == 'primevul':
        label_file = ''
        if slicer_type == 'sysevr':
            sliced_file = ''
        else:
            sliced_file = ''
    
    labeled_data = {}
    with open(label_file, 'r', encoding='utf-8') as f:
        first_char = f.read(1)
        f.seek(0)
        for line in f:
            if line.strip():
                item = json.loads(line)
                if 'idx' in item:
                    labeled_data[item['idx']] = item
    
    sliced_data = {}
    with open(sliced_file, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                item = json.loads(line)
                if 'idx' in item:
                    idx = item['idx']
                    if idx in labeled_data:
                        sliced_data[idx] = item.get('func', '')
    individual_coverage = {}
    stats = {
        'total_samples': 0,
        'matched_samples': 0,
        'samples_with_vul_lines': 0,
        'samples_with_zero_vul_lines': 0,
        'coverage_details': []
    }
    
    total_coverage_sum = 0.0
    answer_count = 0
    # Iterate through all labeled samples
    for idx in labeled_data:
        stats['matched_samples'] += 1
        label_info = labeled_data[idx]
        sliced_func = sliced_data[idx]
        # if sliced_func=='' or sliced_func is None:
        #     answer_count+=1
        #     continue
        # Collect all vulnerability-related lines
        all_vul_lines = []
        for line_info in label_info.get('trigger_lines', []):
            if isinstance(line_info, dict) and 'line_content' in line_info:
                all_vul_lines.append(line_info['line_content'].strip())
        for line_info in label_info.get('related_lines', []):
            if isinstance(line_info, dict) and 'line_content' in line_info:
                all_vul_lines.append(line_info['line_content'].strip())
        
        stats['samples_with_vul_lines'] += 1
        
        # Count lines appearing in sliced code
        matched_count = 0
        sliced_normalized = sliced_func.strip() if sliced_func else ''
        
        # If sliced code is empty, should not match any vulnerability lines
        if not sliced_normalized:
            # Sliced code is empty, all vulnerability lines unmatched
            matched_count = 0
            print(f"Sample {idx} sliced code is empty, coverage is 0%")
        else:
            # Split sliced code by lines and normalize each line
            sliced_lines = [line.strip() for line in sliced_normalized.split('\n') if line.strip()]
            
            # Match vulnerability-related lines line by line
            for vul_line in all_vul_lines:
                vul_line_normalized = vul_line.strip()
                for sliced_line in sliced_lines:
                    # Exact match: vulnerability line exactly equals a line in sliced code
                    # Or inclusion match: vulnerability line is part of a line in sliced code
                    if vul_line_normalized == sliced_line or vul_line_normalized in sliced_line:
                        matched_count += 1
                        break  # Break inner loop after finding match
        
        # Calculate coverage
        vul_cov_i = matched_count / len(all_vul_lines) if len(all_vul_lines) > 0 else 0.0
        individual_coverage[idx] = vul_cov_i
        total_coverage_sum += vul_cov_i
        
        stats['coverage_details'].append({
            'idx': idx,
            'L_vul_size': len(all_vul_lines),
            'matched_count': matched_count,
            'vul_cov': vul_cov_i
        })
    
    stats['total_samples'] = stats['matched_samples']
    
    # Calculate overall average coverage
    if stats['samples_with_vul_lines'] > 0:
        overall_coverage = total_coverage_sum / stats['samples_with_vul_lines']
    else:
        overall_coverage = 0.0
    
    output_file = Path('')
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    results = {
        'overall_coverage': overall_coverage,
        'statistics': stats,
        'individual_coverage': individual_coverage
    }
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    
    all_samples = []
    for detail in stats['coverage_details']:
        vul_cov = detail['vul_cov']
        idx = detail['idx']
        if idx in labeled_data and idx in sliced_data:
            sample_data = {
                'idx': idx,
                'target': labeled_data[idx].get('target'),
                'func_name': labeled_data[idx].get('func_name'),
                'func': sliced_data[idx],
                'vul_coverage': vul_cov,
                'matched_count': detail['matched_count'],
                'L_vul_size': detail['L_vul_size'],
                'trigger_lines': labeled_data[idx].get('trigger_lines', []),
                'related_lines': labeled_data[idx].get('related_lines', [])
            }
            all_samples.append(sample_data)
    


if __name__ == '__main__':
    main()
