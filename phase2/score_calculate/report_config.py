PROMPT_TEMPLATE = """
Role: You are a top-tier code security auditing expert.

Task: 
Carefully analyze the complete context of the following C language code. 
All content in the JSON must come exclusively from the Target Function (marked with "// Target Function"), but you should use the context of Callee Functions (marked with "// Callee Function") to understand the Target Function.

Output requirements (JSON format):
{{
  "high_level_summary": "Describe the functionality and core logic of code using concise and accurate natural language.",
  
  "key_data_flow_paths": [
    {{
      "description": "Describe a critical data flow path.",
      "path": ["variable1", "variable2", "variable3"]
    }}
  ],
  
  "sensitive_operations": [
    {{
      "reason": "Explain why this operation is sensitive.",
      "line_content": "The content of the code line."
    }}
  ],
  
  "control_flow_hotspots": [
    {{
      "reason": "Explain why this control flow construct is worth attention.",
      "line_content": "The content of the code line."
    }}
  ]
}}

Code: {code}
"""
