#!/usr/bin/env python3
import json
import os

def remove_spaces(s: str) -> str:
    """Remove all spaces"""
    return ''.join(s.split())

def find_line(c_file: str, risk_line: str) -> int:
    """Find line number containing risk_line in C file"""
    if not os.path.exists(c_file):
        return -1
    
    risk_no_space = remove_spaces(risk_line)
    if not risk_no_space:
        return -1
    
    with open(c_file, 'r', encoding='utf-8', errors='ignore') as f:
        for i, line in enumerate(f, 1):
            line_no_space = remove_spaces(line)
            # LLM returned line contains source file line (partial match)
            #or risk_no_space in line_no_space
            if (line_no_space in risk_no_space or risk_no_space in line_no_space)and len(line_no_space) > 2:
                return i
    return -1

def main():
    import argparse
    parser = argparse.ArgumentParser(description='Match code line numbers')
    parser.add_argument('--input', default="",
                       help='Input file path')
    parser.add_argument('--c-dir', default="",
                       help='C files directory')
    parser.add_argument('--output', default=None,
                       help='Output file path (default: input filename_numbered.jsonl)')
    
    args = parser.parse_args()
    
    input_file = args.input
    c_dir = args.c_dir
    output_file = args.output or input_file.replace('.jsonl', '_numbered.jsonl')
    
    results = []
    with open(input_file) as f:
        for line in f:
            data = json.loads(line)
            idx = data['idx']
            func_name = data['func_name']
            
            # Adapt to new format: risk_lines is directly a string array
            risk_lines = data.get('risk_lines', [])
            
            c_file = os.path.join(c_dir, f"{idx}.c")
            
            matched = []
            for risk_line in risk_lines:
                # risk_line is now directly a string, no longer an object
                if isinstance(risk_line, str):
                    line_content = risk_line
                elif isinstance(risk_line, dict):
                    # Compatible with old format
                    line_content = risk_line.get('line_content', '')
                else:
                    continue
                
                line_num = find_line(c_file, line_content)
                matched.append({
                    'line_number': line_num,
                    'line_content': line_content,
                })
            
            # Sort by line number
            matched.sort(key=lambda x: x['line_number'])
            
            results.append({'idx': idx, 'target': data['target'], 'func_name': func_name, 'risk_lines': matched})
    
    with open(output_file, 'w') as f:
        for r in results:
            f.write(json.dumps(r, ensure_ascii=False) + '\n')

if __name__ == "__main__":
    main()

