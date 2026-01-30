#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Program slicing tool based on risk lines
Function: Perform backward/forward slicing starting from risk lines identified in Phase 2
"""

import json
import pandas as pd
import re
from typing import List, Dict, Set, Tuple, Optional
from collections import deque
from pathlib import Path
from tqdm import tqdm


class RiskLineSlicer:
    
    def __init__(self, sample_idx: int, parsed_dir: str, c_files_dir: str):

        self.sample_idx = sample_idx
        self.parsed_dir = Path(parsed_dir)
        self.c_files_dir = Path(c_files_dir)
        
        # Sample directory
        self.sample_dir = self.parsed_dir / str(sample_idx)
        self.c_sample_dir = self.c_files_dir / str(sample_idx)
        
        if not self.sample_dir.exists():
            raise FileNotFoundError(f"CPG directory does not exist: {self.sample_dir}")
        
        # Read metadata
        metadata_file = self.sample_dir / 'metadata.json'
        with open(metadata_file, 'r', encoding='utf-8') as f:
            self.metadata = json.load(f)
        
        self.func_name = self.metadata['func_name']
        
        # Cache loaded function CPGs
        self.function_cpgs = {}
        
        # Read callee layer information from original data files
        self.original_callee_layers = {}  # {(func_name, caller): layer}
        self._load_original_callee_layers()
        
        # Load variable names from key_data_flow_paths
        self.key_data_flow_vars = set()  # Store all variable names in key_data_flow_paths
        self._load_key_data_flow_paths()
    
    def _load_original_callee_layers(self):
        """Load callee layer information from original data files"""
        # Try to read from multiple possible original data files
        possible_files = [
            
        ]
        
        for file_path in possible_files:
            file_path_obj = Path(file_path)
            if not file_path_obj.exists():
                continue
            
            try:
                with open(file_path_obj, 'r', encoding='utf-8') as f:
                    for line in f:
                        if not line.strip():
                            continue
                        entry = json.loads(line)
                        if entry.get('idx') == self.sample_idx:
                            # Found matching sample, read callee information
                            callee_list = entry.get('callee', [])
                            for callee in callee_list:
                                func_name = callee.get('func_name')
                                caller = callee.get('caller', '')
                                layer = callee.get('layer')
                                if func_name and layer is not None:
                                    key = (func_name, caller)
                                    # If exists, keep the smaller layer (closer to call chain)
                                    if key not in self.original_callee_layers or layer < self.original_callee_layers[key]:
                                        self.original_callee_layers[key] = layer
                            break
                break
            except Exception as e:
                continue
    
    def _get_callee_layer(self, func_name: str, caller: str, current_layer: int) -> Optional[int]:
        """
        Get layer from original data based on function name and caller
        
        Args:
            func_name: Function name
            caller: Caller function name
            current_layer: Current call chain layer (as fallback)
        
        Returns:
            Layer from original data, or None if not found (use current_layer)
        """
        # First try exact match (func_name, caller)
        key = (func_name, caller)
        if key in self.original_callee_layers:
            return self.original_callee_layers[key]
        
        # If exact match fails, try matching only func_name
        # Find all matching layers
        matching_layers = [layer for (fname, c), layer in self.original_callee_layers.items() 
                          if fname == func_name]
        if matching_layers:
            # Prefer the smallest layer (closer to call chain start, usually from original data)
            return min(matching_layers)
        
        return None
    
    def _load_key_data_flow_paths(self):
        """Load variable names from key_data_flow_paths in Llama_summary.jsonl"""
        summary_file = Path('')
        
        if not summary_file.exists():
            return
        
        try:
            with open(summary_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if not line.strip():
                        continue
                    entry = json.loads(line)
                    if entry.get('idx') == self.sample_idx:
                        summary = entry.get('summary', {})
                        key_data_flow_paths = summary.get('key_data_flow_paths', [])
                        
                        # Extract variable names from all paths
                        for path_info in key_data_flow_paths:
                            path = path_info.get('path', [])
                            for var_name in path:
                                # Process variable names, remove pointer, struct member symbols, keep only base variable names
                                # Example: "avctx->priv_data" -> "avctx", "priv_data"
                                # Example: "atom->size" -> "atom", "size"
                                var_parts = re.split(r'[->\.\[\]]', str(var_name))
                                for part in var_parts:
                                    part = part.strip()
                                    if part and re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', part):
                                        self.key_data_flow_vars.add(part)
                        break
        except Exception as e:
            # If loading fails, continue execution, just key_data_flow_vars will be empty
            pass
    
    def _load_function_cpg(self, func_name: str) -> Optional[Dict]:
        """Load function CPG data"""
        if func_name in self.function_cpgs:
            return self.function_cpgs[func_name]
        
        func_dir = self.sample_dir / func_name
        
        if not func_dir.exists():
            return None
        
        nodes_file = func_dir / 'nodes.csv'
        edges_file = func_dir / 'edges.csv'
        
        if not nodes_file.exists() or not edges_file.exists():
            return None
        
        # Read original C file
        c_file = self.c_sample_dir / f"{func_name}.c"
        if not c_file.exists():
            return None
        
        try:
            with open(c_file, 'r', encoding='utf-8') as f:
                source_lines = f.readlines()
            
            nodes_df = pd.read_csv(nodes_file, sep='\t')
            edges_df = pd.read_csv(edges_file, sep='\t')
            
            cpg_data = {
                'nodes_df': nodes_df,
                'edges_df': edges_df,
                'cfg_nodes': nodes_df[nodes_df['isCFGNode'] == True],
                'cdg_edges': edges_df[edges_df['type'] == 'CONTROLS'],
                'ddg_edges': edges_df[edges_df['type'] == 'REACHES'],
                'key2node': {row['key']: row for _, row in nodes_df.iterrows()},
                'source_lines': source_lines,
                'func_name': func_name
            }
            
            self.function_cpgs[func_name] = cpg_data
            return cpg_data
        
        except Exception as e:
            return None
    
    def _normalize_code(self, code: str) -> str:
        return ''.join(code.split())
    
    def _find_line_number_in_source(self, line_content: str, source_lines: List[str]) -> Optional[int]:
        normalized_target = self._normalize_code(line_content)
        
        for line_num, line in enumerate(source_lines, start=1):
            normalized_line = self._normalize_code(line)
            
            # Bidirectional inclusion matching (supports partial matching)
            if  normalized_line in normalized_target :
                if len(normalized_line) > 2:  # Avoid matching single characters
                    return line_num
        
        return None
    
    def _find_node_by_line_number(self, line_number: int, cpg_data: Dict) -> Optional[int]:
        for idx, row in cpg_data['cfg_nodes'].iterrows():
            if pd.notna(row['location']):
                # location format: "line:column:start_offset:end_offset"
                location_parts = str(row['location']).split(':')
                if len(location_parts) >= 1:
                    try:
                        node_line_number = int(location_parts[0])
                        if node_line_number == line_number:
                            return row['key']
                    except (ValueError, IndexError):
                        continue
        
        return None
    
    def _find_node_by_line_content(self, line_content: str, cpg_data: Dict) -> Optional[int]:
        # Step 1: Find line number in original source code
        line_number = self._find_line_number_in_source(line_content, cpg_data['source_lines'])
        
        if line_number is None:
            return None
        
        # Step 2: Find node in CPG based on line number
        return self._find_node_by_line_number(line_number, cpg_data)
    
    def _find_variable_definition_nodes(self, var_name: str, cpg_data: Dict) -> Set[int]:
        """
        Find all definition nodes of a variable (IdentifierDeclStatement)
        
        Args:
            var_name: Variable name (e.g., 'avbuf')
            cpg_data: Function CPG data
        
        Returns:
            Set of definition node keys
        """
        def_nodes = set()
        
        # Find all CFG nodes of type IdentifierDeclStatement
        for idx, row in cpg_data['cfg_nodes'].iterrows():
            if row['type'] in ['IdentifierDeclStatement', 'DeclStatement'] and pd.notna(row['code']):
                code = str(row['code'])
                # Check if this variable is defined (simple text matching)
                if re.search(r'\b' + re.escape(var_name) + r'\b', code):
                    def_nodes.add(row['key'])
        
        return def_nodes
    
    def _find_function_parameter_nodes(self, param_index: int, cpg_data: Dict) -> Set[int]:
        """
        Find function parameter nodes based on parameter position index
        
        Args:
            param_index: Parameter position index (0 means first parameter)
            cpg_data: Function CPG data
        
        Returns:
            Set of parameter node keys
        """
        param_nodes = set()
        
        # Find all nodes of type MethodParameter or Parameter
        # Need to find parameter at corresponding position in parameter order
        parameter_nodes = []
        for idx, row in cpg_data['nodes_df'].iterrows():
            if row['type'] in ['MethodParameter', 'Parameter', 'MethodParameterIn', 'ParameterIn']:
                # Try to get order field or argumentIndex field for sorting
                order = None
                if 'order' in row and pd.notna(row['order']):
                    try:
                        order = int(row['order'])
                    except:
                        pass
                elif 'argumentIndex' in row and pd.notna(row['argumentIndex']):
                    try:
                        order = int(row['argumentIndex'])
                    except:
                        pass
                elif 'index' in row and pd.notna(row['index']):
                    try:
                        order = int(row['index'])
                    except:
                        pass
                
                # If no order field, try to extract position information from location
                if order is None and pd.notna(row.get('location')):
                    # location format is usually "line:column:start_offset:end_offset"
                    # Simply use line and column numbers as sorting basis (smaller column numbers are usually earlier parameters)
                    try:
                        loc_str = str(row['location'])
                        parts = loc_str.split(':')
                        if len(parts) >= 2:
                            line_num = int(parts[0])
                            col_num = int(parts[1])
                            # Use line*10000 + column as sort key (assuming column number won't exceed 10000)
                            order = line_num * 10000 + col_num
                    except:
                        pass
                
                # If still no order, use node key as sorting basis (as last resort)
                if order is None:
                    order = row['key']
                
                parameter_nodes.append((order, row['key']))
        
        # Sort by order
        parameter_nodes.sort(key=lambda x: x[0])
        
        # If parameter nodes found, take parameter at corresponding position in order
        if param_index < len(parameter_nodes):
            param_key = parameter_nodes[param_index][1]
            param_nodes.add(param_key)
            
            # Find all uses of this parameter (through Identifier nodes)
            # Pre-build AST parent-child relationship index
            if 'ast_children' not in cpg_data:
                ast_children = {}
                for _, row in cpg_data['edges_df'].iterrows():
                    if row['type'] == 'IS_AST_PARENT':
                        parent = row['start']
                        child = row['end']
                        if parent not in ast_children:
                            ast_children[parent] = []
                        ast_children[parent].append(child)
                cpg_data['ast_children'] = ast_children
            
            ast_children = cpg_data['ast_children']
            
            # Get parameter node code (parameter name)
            if param_key in cpg_data['key2node']:
                param_node_row = cpg_data['key2node'][param_key]
                # Handle pandas Series, convert to dict
                if hasattr(param_node_row, 'to_dict'):
                    param_node = param_node_row.to_dict()
                else:
                    param_node = param_node_row
                if param_node and pd.notna(param_node.get('code')):
                    param_name = str(param_node['code']).strip()
                # Extract base variable name
                param_parts = re.split(r'[->\.\[\]]', param_name)
                if param_parts:
                    param_base_name = param_parts[0].strip()
                    # Find all Identifier nodes using this parameter
                    for idx, row in cpg_data['nodes_df'].iterrows():
                        if row['type'] == 'Identifier' and pd.notna(row.get('code')):
                            var_name = str(row['code'])
                            var_parts = re.split(r'[->\.\[\]]', var_name)
                            if var_parts:
                                var_base_name = var_parts[0].strip()
                                if var_base_name == param_base_name:
                                    # Find statement node containing this Identifier (for slicing)
                                    containing_stmt = None
                                    current = row['key']
                                    while current in cpg_data['key2node']:
                                        node = cpg_data['key2node'][current]
                                        if node.get('isCFGNode') == True:
                                            containing_stmt = current
                                            break
                                        # Find parent node
                                        parent_found = False
                                        for _, edge_row in cpg_data['edges_df'].iterrows():
                                            if edge_row['type'] == 'IS_AST_PARENT' and edge_row['end'] == current:
                                                current = edge_row['start']
                                                parent_found = True
                                                break
                                        if not parent_found:
                                            break
                                    
                                    if containing_stmt is not None:
                                        param_nodes.add(containing_stmt)
        
        return param_nodes
    
    def _get_critical_variable_nodes_in_statement(self, stmt_node: int, cpg_data: Dict) -> Set[int]:
        """
        Get critical variable nodes in statement node
        
        Critical variables must have data dependency relationship with variables in key_data_flow_paths
        
        Args:
            stmt_node: Statement node key
            cpg_data: Function CPG data
        
        Returns:
            Set of critical variable node keys
        """
        if not self.key_data_flow_vars:
            # If no key_data_flow_paths, return empty set
            return set()
        
        variable_nodes = set()
        
        # Pre-build AST parent-child relationship index
        if 'ast_children' not in cpg_data:
            ast_children = {}
            for _, row in cpg_data['edges_df'].iterrows():
                if row['type'] == 'IS_AST_PARENT':
                    parent = row['start']
                    child = row['end']
                    if parent not in ast_children:
                        ast_children[parent] = []
                    ast_children[parent].append(child)
            cpg_data['ast_children'] = ast_children
        
        ast_children = cpg_data['ast_children']
        
        # Build data dependency graph (DDG) index: mapping from source nodes to target nodes
        if 'ddg_outgoing' not in cpg_data:
            ddg_outgoing = {}  # {src_node: set([tgt_node1, tgt_node2, ...])}
            for _, row in cpg_data['ddg_edges'].iterrows():
                src = row['start']
                tgt = row['end']
                if src not in ddg_outgoing:
                    ddg_outgoing[src] = set()
                ddg_outgoing[src].add(tgt)
            cpg_data['ddg_outgoing'] = ddg_outgoing
        
        ddg_outgoing = cpg_data['ddg_outgoing']
        
        # Build reverse DDG index (for reverse lookup)
        if 'ddg_incoming' not in cpg_data:
            ddg_incoming = {}  # {tgt_node: set([src_node1, src_node2, ...])}
            for _, row in cpg_data['ddg_edges'].iterrows():
                src = row['start']
                tgt = row['end']
                if tgt not in ddg_incoming:
                    ddg_incoming[tgt] = set()
                ddg_incoming[tgt].add(src)
            cpg_data['ddg_incoming'] = ddg_incoming
        
        ddg_incoming = cpg_data['ddg_incoming']
        
        # Get statement node type
        if stmt_node not in cpg_data['key2node']:
            return set()
        
        stmt_node_obj = cpg_data['key2node'][stmt_node]
        stmt_type = stmt_node_obj.get('type', '')
        
        # Precisely filter variables based on statement type
        candidate_var_nodes = set()
        
        def find_identifiers_in_subtree(root_key, target_types=None):
            """Find Identifier nodes in subtree"""
            identifiers = set()
            visited = set()
            
            def dfs(node_key):
                if node_key in visited:
                    return
                visited.add(node_key)
                
                if node_key not in cpg_data['key2node']:
                    return
                
                node = cpg_data['key2node'][node_key]
                
                # If target types specified, only collect Identifiers in target types
                if target_types is None or node.get('type', '') in target_types:
                    if node['type'] == 'Identifier' and pd.notna(node.get('code')):
                        identifiers.add(node_key)
                
                # Recursively find child nodes
                if node_key in ast_children:
                    for child_key in ast_children[node_key]:
                        dfs(child_key)
            
            dfs(root_key)
            return identifiers
        
        candidate_var_nodes.update(find_identifiers_in_subtree(stmt_node))
        
        # For all candidate variables, must check if they have data dependency relationship with variables in key_data_flow_paths
        for var_node_key in candidate_var_nodes:
            var_node = cpg_data['key2node'][var_node_key]
            var_name = str(var_node.get('code', ''))
            
            # Extract base variable name (remove pointer, struct member symbols)
            var_base_name = None
            if var_name:
                # Handle cases like "var->member" or "var.member" or "var[0]"
                var_parts = re.split(r'[->\.\[\]]', var_name)
                if var_parts:
                    var_base_name = var_parts[0].strip()
            
            # Condition 1: Direct match - if variable name is in key_data_flow_paths, add directly
            if var_base_name and var_base_name in self.key_data_flow_vars:
                variable_nodes.add(var_node_key)
                continue
            
            # Find statement node containing this Identifier (traverse up AST parent nodes until finding CFG node)
            containing_stmt = None
            current = var_node_key
            while current in cpg_data['key2node']:
                node = cpg_data['key2node'][current]
                if node.get('isCFGNode') == True:
                    containing_stmt = current
                    break
                # Find parent node
                parent_found = False
                for _, row in cpg_data['edges_df'].iterrows():
                    if row['type'] == 'IS_AST_PARENT' and row['end'] == current:
                        current = row['start']
                        parent_found = True
                        break
                if not parent_found:
                    break
            
            if containing_stmt is None:
                continue
            
            # Condition 2: Data flow reachable - check if current variable has data flow reachability with variables in key_data_flow_paths
            # Definition of data flow reachability:
            #   - Data flow from key_var definition to current var use (forward data flow)
            #   - Or data flow from current var definition to key_var use (backward data flow)
            has_data_dependency = False
            
            # Find definition nodes of current variable
            var_def_nodes = self._find_variable_definition_nodes(var_base_name, cpg_data) if var_base_name else set()
            
            # Check data flow reachability with variables in key_data_flow_paths
            for key_var_name in self.key_data_flow_vars:
                # Find definition nodes of this variable
                key_var_def_nodes = self._find_variable_definition_nodes(key_var_name, cpg_data)
                
                # Method 1: Forward data flow - data flow from key_var definition to current var use location
                # Check: key_var definition node -> containing_stmt (current var use location)
                # Meaning: key_var value flows to current var use location
                for key_def_node in key_var_def_nodes:
                    if key_def_node in ddg_outgoing:
                        if containing_stmt in ddg_outgoing[key_def_node]:
                            has_data_dependency = True
                            break
                
                if has_data_dependency:
                    break
                
                # Method 2: Backward data flow - data flow from current var definition to key_var use location
                # Check: current var definition node -> key_var use location
                # Meaning: current var value flows to statements using key_var
                if var_def_nodes:
                    # For each definition node of current var, perform forward slice to find all statements using this variable
                    for var_def_node in var_def_nodes:
                        var_forward_slice = self._forward_slice(var_def_node, cpg_data)
                        
                        # Check if forward data flow of key_var definition node (statements using key_var) intersects with var forward slice
                        # If intersection exists, var value flows to statements using key_var, i.e., var and key_var are data flow reachable
                        for key_def_node in key_var_def_nodes:
                            if key_def_node in ddg_outgoing:
                                # Get statements using key_var (forward data flow of key_def_node)
                                key_var_use_stmts = ddg_outgoing[key_def_node]
                                # Check if var forward slice contains statements using key_var
                                if key_var_use_stmts & var_forward_slice:
                                    has_data_dependency = True
                                    break
                        
                        if has_data_dependency:
                            break
                
                if has_data_dependency:
                    break
            
            # Only add variables that pass data dependency check
            if has_data_dependency:
                variable_nodes.add(var_node_key)
        
        return variable_nodes
    
    def _backward_slice(self, key_node: int, cpg_data: Dict) -> Set[int]:
        """
        Backward slice (using CDG + DDG)
        Intra-function backward slice: track control flow and data flow
        """
        pdg_edges = []
        
        for _, row in cpg_data['cdg_edges'].iterrows():
            pdg_edges.append((row['start'], row['end']))
        for _, row in cpg_data['ddg_edges'].iterrows():
            pdg_edges.append((row['start'], row['end']))
        
        slice_nodes = {key_node}
        queue = deque([key_node])
        visited = set()
        
        while queue:
            current = queue.popleft()
            if current in visited:
                continue
            visited.add(current)
            
            for src, tgt in pdg_edges:
                if tgt == current and src not in slice_nodes:
                    slice_nodes.add(src)
                    queue.append(src)
        
        return slice_nodes
    
    def _forward_slice(self, key_node: int, cpg_data: Dict) -> Set[int]:
        """
        Forward slice (using DDG)
        Intra-function forward slice: track data flow
        Note: When slicing across functions, only track forward data flow
        """
        ddg_edge_list = []
        
        for _, row in cpg_data['ddg_edges'].iterrows():
            ddg_edge_list.append((row['start'], row['end']))
        
        slice_nodes = {key_node}
        queue = deque([key_node])
        visited = set()
        
        while queue:
            current = queue.popleft()
            if current in visited:
                continue
            visited.add(current)
            
            for src, tgt in ddg_edge_list:
                if src == current and tgt not in slice_nodes:
                    slice_nodes.add(tgt)
                    queue.append(tgt)
        
        return slice_nodes
    
    def _calculate_end_line_from_offset(self, source_lines: List[str], start_offset: int, end_offset: int) -> int:
        """Calculate end line number from character offset"""
        current_offset = 0
        for line_no, line in enumerate(source_lines, start=1):
            line_length = len(line)
            line_end_offset = current_offset + line_length - 1
            
            if current_offset <= end_offset <= line_end_offset:
                return line_no
            
            current_offset += line_length
        
        return len(source_lines)
    
    def _extract_lines_from_nodes(self, slice_nodes: Set[int], cpg_data: Dict) -> Tuple[List[int], str]:
        """Extract line numbers and code from slice nodes"""
        line_numbers = set()
        source_lines = cpg_data['source_lines']
        
        for node_key in slice_nodes:
            if node_key not in cpg_data['key2node']:
                continue
            
            row = cpg_data['key2node'][node_key]
            location = row['location'] if pd.notna(row['location']) else ''
            
            if location:
                try:
                    parts = location.split(':')
                    start_line = int(parts[0])
                    start_offset = int(parts[2])
                    end_offset = int(parts[3])
                    
                    end_line = self._calculate_end_line_from_offset(source_lines, start_offset, end_offset)
                    
                    for line_no in range(start_line, end_line + 1):
                        line_numbers.add(line_no)
                except:
                    try:
                        start_line = int(parts[0])
                        line_numbers.add(start_line)
                    except:
                        continue
        
        sorted_lines = sorted(line_numbers)
        
        sliced_code_lines = []
        for line_no in sorted_lines:
            if 1 <= line_no <= len(source_lines):
                code_line = source_lines[line_no - 1].rstrip('\n')
                sliced_code_lines.append(code_line)
        
        sliced_code = '\n'.join(sliced_code_lines)
        
        return sorted_lines, sliced_code
    
    def _extract_function_calls_from_nodes(self, slice_nodes: Set[int], cpg_data: Dict) -> Set[str]:
        """Extract function calls from slice nodes"""
        function_calls = set()
        
        for node_key in slice_nodes:
            if node_key not in cpg_data['key2node']:
                continue
            
            row = cpg_data['key2node'][node_key]
            if pd.notna(row['code']):
                code = str(row['code'])
                matches = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', code)
                function_calls.update(matches)
        
        return function_calls
    
    def _extract_function_calls_with_args(self, slice_nodes: Set[int], cpg_data: Dict) -> List[Dict]:
        """
        Extract function calls and their arguments from slice nodes
        
        Returns:
            List[Dict]: Each element contains {'func_name': str, 'call_node': int, 'args': List[str]}
        """
        calls = []
        
        # Pre-build AST parent-child relationship index
        if 'ast_children' not in cpg_data:
            ast_children = {}
            for _, row in cpg_data['edges_df'].iterrows():
                if row['type'] == 'IS_AST_PARENT':
                    parent = row['start']
                    child = row['end']
                    if parent not in ast_children:
                        ast_children[parent] = []
                    ast_children[parent].append(child)
            cpg_data['ast_children'] = ast_children
        
        ast_children = cpg_data['ast_children']
        
        def find_call_expressions_in_subtree(root_key: int, visited: Set[int]) -> List[int]:
            """Find all function call nodes in subtree"""
            call_nodes = []
            if root_key in visited or root_key not in cpg_data['key2node']:
                return call_nodes
            
            visited.add(root_key)
            node_row = cpg_data['key2node'][root_key]
            # Handle pandas Series, convert to dict
            if hasattr(node_row, 'to_dict'):
                node = node_row.to_dict()
            else:
                node = node_row
            node_type = str(node.get('type', ''))
            
            # If current node is function call node, add to result
            if node_type in ['CallExpression', 'Call', 'FunctionCall']:
                call_nodes.append(root_key)
            
            # Recursively find child nodes
            if root_key in ast_children:
                for child_key in ast_children[root_key]:
                    call_nodes.extend(find_call_expressions_in_subtree(child_key, visited))
            
            return call_nodes
        
        processed_call_nodes = set()  # Avoid processing the same function call node repeatedly
        
        # For each slice node, find function calls in its AST subtree
        for cfg_node_key in slice_nodes:
            if cfg_node_key not in cpg_data['key2node']:
                continue
            
            # Find all function calls in AST subtree corresponding to this CFG node
            visited = set()
            call_nodes_in_subtree = find_call_expressions_in_subtree(cfg_node_key, visited)
            
            for call_node_key in call_nodes_in_subtree:
                if call_node_key in processed_call_nodes:
                    continue
                processed_call_nodes.add(call_node_key)
                
                call_node_row = cpg_data['key2node'][call_node_key]
                # Handle pandas Series, convert to dict
                if hasattr(call_node_row, 'to_dict'):
                    call_node = call_node_row.to_dict()
                else:
                    call_node = call_node_row
                node_type = str(call_node.get('type', ''))
                
                # Ensure it's a function call node
                if node_type in ['CallExpression', 'Call', 'FunctionCall']:
                    # Extract function name and arguments
                    func_name = None
                    args = []
                    
                    # Find function name (usually first child node)
                    if call_node_key in ast_children and len(ast_children[call_node_key]) > 0:
                        # First child node is usually function name
                        first_child = ast_children[call_node_key][0]
                        if first_child in cpg_data['key2node']:
                            func_name_node_row = cpg_data['key2node'][first_child]
                            if hasattr(func_name_node_row, 'to_dict'):
                                func_name_node = func_name_node_row.to_dict()
                            else:
                                func_name_node = func_name_node_row
                            if pd.notna(func_name_node.get('code')):
                                func_name = str(func_name_node['code']).strip()
                        
                        # Find argument list node
                        for child_key in ast_children[call_node_key]:
                            if child_key in cpg_data['key2node']:
                                child_node_row = cpg_data['key2node'][child_key]
                                if hasattr(child_node_row, 'to_dict'):
                                    child_node = child_node_row.to_dict()
                                else:
                                    child_node = child_node_row
                                if child_node and str(child_node.get('type', '')) in ['ArgumentList', 'Argument']:
                                    # Extract variable names from arguments
                                    self._extract_args_from_subtree(child_key, args, cpg_data, ast_children)
                    
                    # If not found via AST, try parsing from code
                    if not func_name and pd.notna(call_node.get('code')):
                        code = str(call_node['code'])
                        # Extract function name
                        func_match = re.search(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', code)
                        if func_match:
                            func_name = func_match.group(1)
                            # Extract arguments
                            args_match = re.search(r'\((.*?)\)', code)
                            if args_match:
                                args_str = args_match.group(1)
                                # Simply extract variable names from arguments (comma-separated)
                                for arg in args_str.split(','):
                                    arg = arg.strip()
                                    # Extract variable name (remove operators, parentheses, etc.)
                                    var_match = re.search(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b', arg)
                                    if var_match:
                                        args.append(var_match.group(1))
                    
                    if func_name:
                        calls.append({
                            'func_name': func_name,
                            'call_node': call_node_key,
                            'args': args
                        })
        
        return calls
    
    def _extract_args_from_subtree(self, root_key: int, args: List[str], cpg_data: Dict, ast_children: Dict):
        """Extract argument variable names from subtree"""
        if root_key not in cpg_data['key2node']:
            return
        
        node = cpg_data['key2node'][root_key]
        
        # If Identifier node, extract variable name
        if node['type'] == 'Identifier' and pd.notna(node.get('code')):
            var_name = str(node['code']).strip()
            # Extract base variable name
            var_parts = re.split(r'[->\.\[\]]', var_name)
            if var_parts:
                base_name = var_parts[0].strip()
                if base_name and base_name not in args:
                    args.append(base_name)
        
        # Recursively find child nodes
        if root_key in ast_children:
            for child_key in ast_children[root_key]:
                self._extract_args_from_subtree(child_key, args, cpg_data, ast_children)
    
    def slice_from_risk_lines(self, risk_lines: List[str], target: int = 0, max_depth: int = 2) -> Dict:


        # Load main function CPG
        cpg_data = self._load_function_cpg(self.func_name)
        if cpg_data is None:
            return None
        
        # Find nodes corresponding to risk lines
        risk_nodes = []
        matched_lines = []
        
        for line_content in risk_lines:
            node_key = self._find_node_by_line_content(line_content, cpg_data)
            if node_key is not None:
                risk_nodes.append(node_key)
                matched_lines.append(line_content)
        
        if not risk_nodes:
            return None
        # Slice and merge each risk node
        all_slice_nodes = set()
        
        for risk_node in risk_nodes:
            # Step 1: Extract critical variables in statement
            variable_identifier_nodes = self._get_critical_variable_nodes_in_statement(risk_node, cpg_data)
            
            # Step 2: If critical variables exist, perform bidirectional slice starting from critical variable nodes
            if variable_identifier_nodes:
                # For each critical variable node, perform bidirectional slice starting from it
                for var_node in variable_identifier_nodes:
                    # Perform bidirectional slice starting from critical variable node
                    backward = self._backward_slice(var_node, cpg_data)
                    forward = self._forward_slice(var_node, cpg_data)
                    all_slice_nodes.update(backward)
                    all_slice_nodes.update(forward)
            else:
                # If critical variables empty, fall back to bidirectional slice of risk node itself (as fallback)
                backward = self._backward_slice(risk_node, cpg_data)
                forward = self._forward_slice(risk_node, cpg_data)
                all_slice_nodes.update(backward)
                all_slice_nodes.update(forward)
        
        # Keep all nodes with location information (including CFG and AST nodes)
        # This ensures no line number information is lost
        nodes_with_location = set()
        for n in all_slice_nodes:
            if n in cpg_data['key2node']:
                node = cpg_data['key2node'][n]
                # If location information exists, keep this node
                if pd.notna(node.get('location')):
                    nodes_with_location.add(n)
        all_slice_nodes = nodes_with_location
        
        # Extract line numbers and code
        line_numbers, sliced_code = self._extract_lines_from_nodes(all_slice_nodes, cpg_data)
        
        # Calculate compression rate
        original_lines = len(cpg_data['source_lines'])
        sliced_lines = len(line_numbers)
        compression_rate = round((1 - sliced_lines / original_lines) * 100, 2) if original_lines > 0 else 0
        
        # Extract function calls and their arguments
        function_calls_with_args = self._extract_function_calls_with_args(all_slice_nodes, cpg_data)
        
        # Recursively slice called functions (flattened structure)
        callee_results = []
        if max_depth > 0 and function_calls_with_args:
            available_callees = set(self.metadata.get('callee_files', []))
            available_callees = {Path(f).stem for f in available_callees}
            
            sliced_funcs = {self.func_name}  # Avoid circular recursion
            
            for call_info in function_calls_with_args:
                called_func = call_info['func_name']
                args = call_info.get('args', [])
                
                # Check if function is in available callee list
                if called_func in available_callees and called_func not in sliced_funcs:
                    # Extract positions of key arguments (positions of arguments in key_data_flow_vars)
                    key_arg_indices = []  # Store index positions of key arguments
                    if self.key_data_flow_vars:
                        for idx, arg in enumerate(args):
                            # Extract base variable name of argument
                            arg_parts = re.split(r'[->\.\[\]]', arg)
                            if arg_parts:
                                arg_base_name = arg_parts[0].strip()
                                if arg_base_name in self.key_data_flow_vars:
                                    key_arg_indices.append(idx)  # Record argument position
                    
                    # Only perform recursive slice if key arguments exist
                    if key_arg_indices:
                        self._recursive_slice_callee_flat(
                            called_func, 
                            self.func_name,
                            1,
                            max_depth - 1, 
                            sliced_funcs,
                            callee_results,
                            key_arg_indices  # Pass index positions of key arguments
                        )
        
        # Calculate compression rate of entire context (including all called functions)
        total_original_lines = original_lines
        total_sliced_lines = sliced_lines
        
        for callee in callee_results:
            # Get original and sliced line counts from callee
            callee_original = callee.get('original_lines', 0)
            callee_sliced = callee.get('sliced_lines', 0)
            
            total_original_lines += callee_original
            total_sliced_lines += callee_sliced
        
        total_compression_rate = round((1 - total_sliced_lines / total_original_lines) * 100, 2) if total_original_lines > 0 else 0
        
        # If sliced code is empty, use original risk lines as slice result
        if not sliced_code or not sliced_code.strip():
            sliced_code = '\n'.join(risk_lines)
            # Recalculate sliced line count
            total_sliced_lines = len(risk_lines)
            total_compression_rate = round((1 - total_sliced_lines / total_original_lines) * 100, 2) if total_original_lines > 0 else 0
        
        return {
            'idx': self.sample_idx,
            'target': target,
            'func_name': self.func_name,
            'total_original_lines': total_original_lines,
            'total_sliced_lines': total_sliced_lines,
            'total_compression_rate': total_compression_rate,
            'risk_lines_matched': matched_lines,
            'func': sliced_code,
            'callee': callee_results
        }
    
    def _recursive_slice_callee_flat(self, func_name: str, caller: str, layer: int, 
                                     remaining_depth: int, sliced_funcs: Set[str], 
                                     callee_results: List[Dict], key_arg_indices: List[int] = None):
        """
        Recursively slice called functions (flattened structure, mark caller and layer)
        Inter-procedural slice: only track forward data flow (using _forward_slice, based on DDG)
        
        Args:
            func_name: Called function name
            caller: Caller function name
            layer: Current layer
            remaining_depth: Remaining recursion depth
            sliced_funcs: Set of already sliced functions
            callee_results: Flattened callee list (will be modified)
            key_arg_indices: List of key argument position indices (argument positions at call site)
        """
        if remaining_depth <= 0 or func_name in sliced_funcs:
            return
        
        sliced_funcs.add(func_name)
        
        # Load called function CPG
        cpg_data = self._load_function_cpg(func_name)
        if cpg_data is None:
            return
        
        # Inter-procedural slice: track forward data flow of key arguments, and variables with direct or indirect dependency
        # If no key arguments, don't slice
        if not key_arg_indices or len(key_arg_indices) == 0:
            return
        
        slice_nodes = set()
        dependent_vars = set()  # Store all variables with dependency relationship with key arguments
        
        if key_arg_indices and len(key_arg_indices) > 0:
            # For passed key argument positions, find corresponding parameter nodes in callee function and perform forward data flow slice
            for param_index in key_arg_indices:
                # Find corresponding parameter node based on parameter position index
                param_nodes = self._find_function_parameter_nodes(param_index, cpg_data)
                
                # Perform forward and backward slice on each parameter node (track data flow)
                for param_node in param_nodes:
                    # Forward slice: find all places using this parameter
                    forward_slice = self._forward_slice(param_node, cpg_data)
                    # Backward slice: find places affecting this parameter definition (if indirect dependency)
                    backward_slice = self._backward_slice(param_node, cpg_data)
                    slice_nodes.update(forward_slice)
                    slice_nodes.update(backward_slice)
                
                # Extract parameter names from parameter nodes for subsequent dependency tracking
                for param_node_key in param_nodes:
                    if param_node_key in cpg_data['key2node']:
                        param_node_row = cpg_data['key2node'][param_node_key]
                        # Handle pandas Series, convert to dict
                        if hasattr(param_node_row, 'to_dict'):
                            param_node = param_node_row.to_dict()
                        else:
                            param_node = param_node_row
                        if param_node and pd.notna(param_node.get('code')):
                            param_name = str(param_node['code']).strip()
                            param_parts = re.split(r'[->\.\[\]]', param_name)
                            if param_parts:
                                param_base_name = param_parts[0].strip()
                                dependent_vars.add(param_base_name)
            
            # After first round of slicing, identify all variables in slice with data dependency relationship with key arguments
            # Then also slice these variables (expand dependency relationship)
            prev_slice_size = 0
            max_iterations = 5  # Avoid infinite loop
            iteration = 0
            
            while len(slice_nodes) > prev_slice_size and iteration < max_iterations:
                prev_slice_size = len(slice_nodes)
                iteration += 1
                
                # Extract all variables from current slice nodes
                # Pre-build AST parent-child relationship index
                if 'ast_children' not in cpg_data:
                    ast_children = {}
                    for _, row in cpg_data['edges_df'].iterrows():
                        if row['type'] == 'IS_AST_PARENT':
                            parent = row['start']
                            child = row['end']
                            if parent not in ast_children:
                                ast_children[parent] = []
                            ast_children[parent].append(child)
                    cpg_data['ast_children'] = ast_children
                
                ast_children = cpg_data['ast_children']
                
                # Find all variables in slice nodes
                def find_identifiers_in_slice_nodes(slice_nodes, cpg_data, ast_children):
                    identifiers = set()
                    for node_key in slice_nodes:
                        if node_key not in cpg_data['key2node']:
                            continue
                        
                        def dfs_identifiers(current):
                            if current not in cpg_data['key2node']:
                                return
                            
                            node = cpg_data['key2node'][current]
                            if node['type'] == 'Identifier' and pd.notna(node.get('code')):
                                var_name = str(node['code'])
                                var_parts = re.split(r'[->\.\[\]]', var_name)
                                if var_parts:
                                    var_base_name = var_parts[0].strip()
                                    if var_base_name and re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', var_base_name):
                                        identifiers.add(var_base_name)
                            
                            if current in ast_children:
                                for child in ast_children[current]:
                                    dfs_identifiers(child)
                        
                        dfs_identifiers(node_key)
                    return identifiers
                
                slice_vars = find_identifiers_in_slice_nodes(slice_nodes, cpg_data, ast_children)
                
                # For newly discovered variables, check if they have data dependency relationship with key arguments
                for var_name in slice_vars:
                    if var_name not in dependent_vars:
                        # Check if this variable has data dependency with key arguments
                        var_def_nodes = self._find_variable_definition_nodes(var_name, cpg_data)
                        
                        # Check: whether this variable's definition is affected by key arguments, or this variable's use affects key arguments
                        has_dependency = False
                        # Use key argument names in dependent_vars to check dependency relationship
                        for key_param in dependent_vars:
                            key_param_def_nodes = self._find_variable_definition_nodes(key_param, cpg_data)
                            
                            # Build data dependency graph index
                            if 'ddg_outgoing' not in cpg_data:
                                ddg_outgoing = {}
                                for _, row in cpg_data['ddg_edges'].iterrows():
                                    src = row['start']
                                    tgt = row['end']
                                    if src not in ddg_outgoing:
                                        ddg_outgoing[src] = set()
                                    ddg_outgoing[src].add(tgt)
                                cpg_data['ddg_outgoing'] = ddg_outgoing
                            
                            ddg_outgoing = cpg_data['ddg_outgoing']
                            
                            # Check data dependency relationship
                            for key_def in key_param_def_nodes:
                                for var_def in var_def_nodes:
                                    # Method 1: data flow from key argument to this variable
                                    if key_def in ddg_outgoing:
                                        # Check if var_def is in forward slice of key_def
                                        key_forward = self._forward_slice(key_def, cpg_data)
                                        if var_def in key_forward:
                                            has_dependency = True
                                            break
                                    
                                    # Method 2: data flow from this variable to key argument
                                    if var_def in ddg_outgoing:
                                        var_forward = self._forward_slice(var_def, cpg_data)
                                        # Check if key argument use is in forward slice of var_def
                                        if key_def in var_forward or any(key_use in var_forward 
                                                                        for key_use in key_param_def_nodes):
                                            has_dependency = True
                                            break
                                
                                if has_dependency:
                                    break
                            
                            if has_dependency:
                                break
                        
                        # If dependency relationship exists, also slice this variable
                        if has_dependency:
                            dependent_vars.add(var_name)
                            for var_def_node in var_def_nodes:
                                var_forward = self._forward_slice(var_def_node, cpg_data)
                                var_backward = self._backward_slice(var_def_node, cpg_data)
                                slice_nodes.update(var_forward)
                                slice_nodes.update(var_backward)
            
            # Keep all nodes with location information (including CFG and AST nodes)
            # This ensures no line number information is lost
            nodes_with_location = set()
            for n in slice_nodes:
                if n in cpg_data['key2node']:
                    node = cpg_data['key2node'][n]
                    # If location information exists, keep this node
                    if pd.notna(node.get('location')):
                        nodes_with_location.add(n)
            slice_nodes = nodes_with_location
        
        # Extract line numbers and code
        line_numbers, sliced_code = self._extract_lines_from_nodes(slice_nodes, cpg_data)
        
        # Calculate original line count
        original_lines = len(cpg_data['source_lines'])
        sliced_lines = len(line_numbers)
        
        # Prefer getting layer from original data
        original_layer = self._get_callee_layer(func_name, caller, layer)
        if original_layer is not None:
            layer = original_layer
        # If not in original data, use call chain layer (determined by layer parameter passed during recursive call)
        
        # Add to flattened list
        callee_results.append({
            'layer': layer,
            'func_name': func_name,
            'func_str': sliced_code,
            'caller': caller,
            'original_lines': original_lines,
            'sliced_lines': sliced_lines
        })
        
        # Extract function calls and their arguments in this function (from slice nodes)
        function_calls_with_args = self._extract_function_calls_with_args(slice_nodes, cpg_data)
        
        # Continue recursive slicing
        if remaining_depth > 1:
            available_callees = set(self.metadata.get('callee_files', []))
            available_callees = {Path(f).stem for f in available_callees}
            
            for call_info in function_calls_with_args:
                called_func = call_info['func_name']
                args = call_info.get('args', [])
                
                if called_func in available_callees and called_func not in sliced_funcs:
                    # Extract key argument position indices: check if argument list has variables with dependency relationship with key arguments
                    next_key_arg_indices = []
                    
                    # Check if argument list has variables with dependency relationship with key arguments
                    for idx, arg in enumerate(args):
                        arg_parts = re.split(r'[->\.\[\]]', arg)
                        if arg_parts:
                            arg_base_name = arg_parts[0].strip()
                            # If variable is in key_data_flow_vars, or has dependency relationship with key arguments
                            if (self.key_data_flow_vars and arg_base_name in self.key_data_flow_vars) or \
                               (dependent_vars and arg_base_name in dependent_vars):
                                if idx not in next_key_arg_indices:
                                    next_key_arg_indices.append(idx)
                    
                    # Only perform recursive slice if key arguments exist
                    if next_key_arg_indices:
                        self._recursive_slice_callee_flat(
                            called_func,
                            func_name,  # Current function as caller for next layer
                            layer + 1,
                            remaining_depth - 1,
                            sliced_funcs,
                            callee_results,
                            next_key_arg_indices  # Pass key argument position indices
                        )


def batch_slice_from_final_risk_lines(
    risk_file: str,
    parsed_dir: str,
    c_files_dir: str,
    output_file: str,
    max_depth: int = 2,
    limit: int = None
):
    """
    Batch processing: read risk lines from final_risk_lines.jsonl and perform slicing
    
    Args:
        risk_file: Path to final_risk_lines.jsonl
        parsed_dir: CPG directory after Joern parsing
        c_files_dir: Original C files directory
        output_file: Output file path
        max_depth: Maximum recursion depth
        limit: Limit number of samples to process
    """
    # Read risk line data
    risk_data = []
    with open(risk_file, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                risk_data.append(json.loads(line))
    
    if limit:
        risk_data = risk_data[:limit]
    
    # Process each sample
    results = []
    failed = []
    
    for data in tqdm(risk_data, desc="Slicing progress"):
        idx = data['idx']
        func_name = data['func_name']
        target = data.get('target', 0)
        risk_lines = data.get('final_risk_lines', [])
        
        if not risk_lines:
            continue
        
        try:
            slicer = RiskLineSlicer(idx, parsed_dir, c_files_dir)
            result = slicer.slice_from_risk_lines(risk_lines, target, max_depth)
            
            if result:
                results.append(result)
            else:
                failed.append(idx)
        
        except Exception as e:
            failed.append(idx)
    
    # Save results
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        for result in results:
            f.write(json.dumps(result, ensure_ascii=False) + '\n')


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Program slicing tool based on risk lines')
    parser.add_argument('--risk-file',
                       default='',
                       help='Risk line file')
    parser.add_argument('--parsed-dir',
                       default='',
                       help='CPG directory after Joern parsing')
    parser.add_argument('--c-files-dir',
                       default='',
                       help='Original C files directory')
    parser.add_argument('--output-file',
                       default='',
                       help='Output file path')
    parser.add_argument('--max-depth',
                       type=int,
                       default=4,
                       help='Maximum recursion depth')
    parser.add_argument('--limit',
                       type=int,
                       default=99999,
                       help='Limit number of samples to process (for testing)')
    
    args = parser.parse_args()
    
    batch_slice_from_final_risk_lines(
        args.risk_file,
        args.parsed_dir,
        args.c_files_dir,
        args.output_file,
        args.max_depth+1,
        args.limit
    )


if __name__ == '__main__':
    main()

