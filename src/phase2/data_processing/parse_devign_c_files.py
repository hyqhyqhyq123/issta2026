#!/usr/bin/env python3

import os
import subprocess
import glob
from pathlib import Path
from tqdm import tqdm
import json
import shutil

# 静默输出：将 QUIET 设为 True 以屏蔽非必要日志（保留文件写入与返回值，不影响功能）
from builtins import print as _builtin_print
QUIET: bool = True

def print(*args, **kwargs):  # type: ignore[override]
    if not QUIET:
        _builtin_print(*args, **kwargs)


def parse_single_c_file(c_file: Path, sample_dir: Path, output_base_dir: Path, joern_dir: str) -> tuple:
    """
    解析单个C文件，生成 nodes.csv 和 edges.csv

    Args:
        c_file: C文件路径
        sample_dir: 样本目录（idx_target，用于读取C文件）
        output_base_dir: 输出根目录
        joern_dir: Joern工具目录

    Returns:
        (success, message, output_dir)
    """
    import time

    func_name = c_file.stem  # 文件名（不含.c）

    # 创建输出目录：output_base_dir/idx_target/func_name/
    sample_name = sample_dir.name  # 如 0_0
    output_sample_dir = output_base_dir / sample_name
    output_dir = output_sample_dir / func_name
    output_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        'bash', 'slicer.sh',
        str(sample_dir),  # C文件所在目录
        c_file.name,       # 文件名
        '3',               # 行号（这里用1，实际可能需要调整）
        str(output_dir)    # 输出目录
    ]

    max_retries = 5
    attempt = 0
    while attempt < max_retries:
        try:
            result = subprocess.run(
                cmd,
                cwd=joern_dir,
                capture_output=True,
                text=True,
                timeout=60
            )

            # Joern 生成的临时文件路径
            temp_nodes = os.path.join(joern_dir, 'parsed', 'tmp', c_file.name, 'nodes.csv')
            temp_edges = os.path.join(joern_dir, 'parsed', 'tmp', c_file.name, 'edges.csv')

            # 目标文件路径
            target_nodes = output_dir / 'nodes.csv'
            target_edges = output_dir / 'edges.csv'

            # 复制文件
            if os.path.exists(temp_nodes) and os.path.exists(temp_edges):
                shutil.copy2(temp_nodes, target_nodes)
                shutil.copy2(temp_edges, target_edges)
                return True, f"成功", output_dir
            else:
                raise RuntimeError(f"未生成CSV文件: {c_file.name}")

        except Exception as e:
            attempt += 1
            if attempt >= max_retries:
                return False, f"解析失败（重试{max_retries}次）：{e}", output_dir
            else:
                time.sleep(1)  # 稍作延迟后尝试重试



def parse_sample_directory(sample_dir: Path, output_base_dir: Path, joern_dir: str) -> dict:
    """
    解析样本目录中的所有C文件
    
    Args:
        sample_dir: 样本目录路径（如 0_0/）
        output_base_dir: 输出根目录
        joern_dir: Joern工具目录
        
    Returns:
        统计信息字典
    """
    # 获取所有C文件
    c_files = list(sample_dir.glob('*.c'))
    
    stats = {
        'sample': sample_dir.name,
        'total_c_files': len(c_files),
        'success': 0,
        'failed': 0,
        'failed_files': []
    }
    
    # 复制 metadata.json 到输出样本目录
    sample_name = sample_dir.name  # 如 0_0
    output_sample_dir = output_base_dir / sample_name
    output_sample_dir.mkdir(parents=True, exist_ok=True)
    
    metadata_src = sample_dir / 'metadata.json'
    if metadata_src.exists():
        metadata_dst = output_sample_dir / 'metadata.json'
        shutil.copy2(metadata_src, metadata_dst)
    
    for c_file in c_files:
        success, message, output_dir = parse_single_c_file(c_file, sample_dir, output_base_dir, joern_dir)
        
        if success:
            stats['success'] += 1
        else:
            stats['failed'] += 1
            stats['failed_files'].append({
                'file': c_file.name,
                'reason': message
            })
    
    return stats


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='解析 devign_c_files 中的所有C文件')
    parser.add_argument('--input-dir',
                       default='',
                       help='C文件根目录')
    parser.add_argument('--output-dir',
                       default='',
                       help='输出根目录')
    parser.add_argument('--joern-dir',
                       default='',
                       help='Joern工具目录')
    parser.add_argument('--limit',
                       type=int,
                       default=None,
                       help='限制处理的样本数量（测试用）')
    parser.add_argument('--start',
                       type=int,
                       default=202529,
                       help='')
    
    args = parser.parse_args()
    
    # 静默：如需调试将 QUIET=False
    
    # 获取所有样本目录
    input_base = Path(args.input_dir)
    output_base = Path(args.output_dir)
    output_base.mkdir(parents=True, exist_ok=True)
    
    # 按照 idx 数字排序（而不是字符串排序）
    # 目录名格式: 纯数字字符串，对应 idx
    def get_idx(dir_path):
        try:
            return int(dir_path.name)
        except ValueError:
            return 0
    
    sample_dirs = sorted([d for d in input_base.iterdir() if d.is_dir()], key=get_idx)
    
    # 应用 start 和 limit
    if args.start > 0:
        sample_dirs = [d for d in sample_dirs if get_idx(d) >= args.start]
        # 静默
    
    if args.limit:
        sample_dirs = sample_dirs[:args.limit]
        # 静默
    
    # 静默
    
    # 批量处理
    all_stats = []
    total_success = 0
    total_failed = 0
    print(f"解析样本: {len(sample_dirs)}")
    for sample_dir in tqdm(sample_dirs, desc="解析样本"):
        stats = parse_sample_directory(sample_dir, output_base, args.joern_dir)
        all_stats.append(stats)
        total_success += stats['success']
        total_failed += stats['failed']
        # 注意：并行运行时禁用清理，避免删除其他批次的临时文件！
        # 清理操作会在所有批次完成后手动执行
        if len(all_stats) % 1 == 0:
            print(f"清理临时文件: {len(all_stats)}")
            cleanup_script = os.path.join(args.joern_dir, 'force_cleanup_every_second.sh')
            if os.path.exists(cleanup_script):
                subprocess.run(['bash', cleanup_script], capture_output=True)
    
    # 汇总统计
    # 静默
    
    # 显示有失败的样本
    failed_samples = [s for s in all_stats if s['failed'] > 0]
    # 静默
    
    # 保存统计信息
    stats_file = output_base / 'parse_stats.json'
    with open(stats_file, 'w', encoding='utf-8') as f:
        json.dump({
            'total_samples': len(all_stats),
            'total_c_files_success': total_success,
            'total_c_files_failed': total_failed,
            'samples': all_stats
        }, f, indent=2)
    
    # 静默


if __name__ == "__main__":
    main()

