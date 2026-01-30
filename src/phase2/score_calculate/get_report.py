#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phase 1 - Call LLM to generate global summary
"""

import json
import os
import sys
import time
import asyncio
import aiohttp
from concurrent.futures import ThreadPoolExecutor, as_completed
from openai import OpenAI
from pathlib import Path
import report_config

# Import unified utility functions
sys.path.insert(0, str(Path(__file__).parent.parent))
from common import truncate_text, extract_json_from_text, retry_with_backoff

# Set unbuffered output
os.environ['PYTHONUNBUFFERED'] = '1'

# Temporarily disable proxy to avoid connection issues
os.environ.pop('http_proxy', None)
os.environ.pop('https_proxy', None)
os.environ.pop('HTTP_PROXY', None)
os.environ.pop('HTTPS_PROXY', None)
os.environ.pop('all_proxy', None)
os.environ.pop('ALL_PROXY', None)
for proxy_var in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
    os.environ.pop(proxy_var, None)

client = OpenAI(
    api_key=report_config.OPENAI_API_KEY,
    base_url=report_config.OPENAI_BASE_URL
)


def call_llm(code_context: str):
    # Truncate code to prevent exceeding token limit
    code_context = truncate_text(code_context, max_chars=report_config.MAX_CHARS)
    
    prompt = report_config.PROMPT_TEMPLATE.format(code=code_context)
    
    messages = [
        {"role": "system", "content": "You are a top-tier code security auditing expert."},
        {"role": "user", "content": prompt}
    ]
    
    try:
        resp = client.chat.completions.create(
            model=report_config.MODEL_NAME,
            messages=messages,
            temperature=report_config.TEMPERATURE,
            max_tokens=report_config.MAX_TOKENS,
            response_format={'type': 'json_object'}
        )
        
        # Check response
        if not resp or not resp.choices or not resp.choices[0].message.content:
            raise ValueError(f"Model returned empty response: {resp}")
        
        # Get content
        content = resp.choices[0].message.content
        
        # Use unified JSON extraction function
        result = extract_json_from_text(content)
        return result, content  # Return parsed result and original content
        
    except Exception as e:
        if 'content' in locals():
            raise ValueError(f"{e}\nOriginal content: {content[:500]}")
        raise

def process_single_sample(sample_data):
    """
    Function to process a single sample, for concurrent execution
    
    Args:
        sample_data: Dictionary containing idx, sample, layer information
        
    Returns:
        dict: Processing result, containing success, idx, result, error information
    """
    idx, sample, layer = sample_data['idx'], sample_data['sample'], sample_data['layer']
    
    try:
        # Build code context
        code_context = f"// Target Function\n{sample['func']}\nfunc_name: {sample['func_name']}\n"
        for callee in sample.get('callee', []):
            if callee.get("layer") <= layer:
                code_context += f"\n// Callee Function: {callee.get('func_name', '')} (Caller: {callee.get('caller', '')})\n{callee['func_str']}\n"
        
        result = retry_with_backoff(
            lambda: call_llm(code_context),
            max_retries=3,
            base_delay=1.0
        )
        global_summary = result
        return {
            'success': True,
            'idx': idx,
            'result': {
                'idx': idx,
                'target': sample['target'],
                'func_name': sample['func_name'],
                'summary': global_summary
            },
            'error': None
        }
        
    except Exception as e:
        return {
            'success': False,
            'idx': idx,
            'result': None,
            'error': f"idx: {idx} | func: {sample['func_name']}\nError: {e}\n{'='*60}\n\n"
        }

def main():
    """Main function"""
    import sys
    
    # Read parameters from config file
    start_idx = report_config.START_IDX
    end_idx = report_config.END_IDX
    samples_str = report_config.SAMPLES
    samples_file = report_config.SAMPLES_FILE
    max_tokens_override = report_config.MAX_TOKENS_OVERRIDE
    concurrency_override = report_config.CONCURRENCY_OVERRIDE
    tier_override = report_config.TIER_OVERRIDE
    current_concurrency = concurrency_override
    
    with open(report_config.INPUT_JSONL, 'r') as f:
        samples = [json.loads(line) for line in f]
    
    idx_to_sample = {sample['idx']: sample for sample in samples}
    all_indices = sorted(idx_to_sample.keys())
    
    if samples_str:
        target_indices = [int(idx.strip()) for idx in samples_str.split(',')]
    elif samples_file:
        with open(samples_file, 'r') as f:
            content = f.read().strip()
            target_indices = [int(idx.strip()) for idx in content.split(',') if idx.strip().isdigit()]
    elif start_idx is not None and end_idx is not None:
        target_indices = [idx for idx in all_indices if start_idx <= idx < end_idx]
    elif end_idx is not None:
        target_indices = [idx for idx in all_indices if idx < end_idx]
    else:
        return
    target_indices = [idx for idx in target_indices if idx in idx_to_sample]
    
    layer = report_config.LAYER
    output_dir = Path(report_config.OUTPUT_DIR)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    if len(target_indices) <= 10:
        batch_name = f"idx_{'_'.join(map(str, target_indices))}"
    else:
        batch_name = f"batch_{target_indices[0]}_{target_indices[-1]+1}"
    
    output_file = output_dir / f"summary_{batch_name}.jsonl"
    error_file = output_dir / f"errors_{batch_name}.txt"
    error_indices_file = output_dir / f"error_indices_{batch_name}.txt"
    
    sample_data_list = []
    for idx in target_indices:
        sample_data_list.append({
            'idx': idx,
            'sample': idx_to_sample[idx],
            'layer': layer
        })
    
    success_count = 0
    error_count = 0
    error_indices = []
    
    with open(output_file, 'a', encoding='utf-8') as out_f, \
         open(error_file, 'a', encoding='utf-8') as err_f, \
         open(error_indices_file, 'a', encoding='utf-8') as err_indices_f:
        
        with ThreadPoolExecutor(max_workers=current_concurrency) as executor:
            future_to_data = {
                executor.submit(process_single_sample, data): data 
                for data in sample_data_list
            }
            
            for i, future in enumerate(as_completed(future_to_data), 1):
                data = future_to_data[future]
                idx = data['idx']
                sample = data['sample']
                
                try:
                    result = future.result()
                    
                    if result['success']:
                        out_f.write(json.dumps(result['result'], ensure_ascii=False) + '\n')
                        out_f.flush()
                        success_count += 1
                    else:
                        err_f.write(result['error'])
                        err_indices_f.write(f"{idx},")
                        err_f.flush()
                        err_indices_f.flush()
                        error_count += 1
                        error_indices.append(idx)
                        
                except Exception as e:
                    error_msg = f"idx: {idx} | func: {sample['func_name']}\nUnexpected error: {e}\n{'='*60}\n\n"
                    err_f.write(error_msg)
                    err_indices_f.write(f"{idx},")
                    err_f.flush()
                    err_indices_f.flush()
                    error_count += 1
                    error_indices.append(idx)
        

if __name__ == "__main__":
    main()
