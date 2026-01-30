"""
Phase 1 configuration file
"""

import os

# User tier configuration
USER_TIERS = {
    'Free': {'concurrency': 1, 'rpm': 3, 'tpm': 32000, 'tpd': 1500000},
    'Tier1': {'concurrency': 50, 'rpm': 200, 'tpm': 128000, 'tpd': 10000000},
    'Tier2': {'concurrency': 100, 'rpm': 500, 'tpm': 128000, 'tpd': 20000000},
    'Tier3': {'concurrency': 200, 'rpm': 5000, 'tpm': 384000, 'tpd': None},
    'Tier4': {'concurrency': 400, 'rpm': 5000, 'tpm': 768000, 'tpd': None},
    'Tier5': {'concurrency': 1000, 'rpm': 10000, 'tpm': 2000000, 'tpd': None}
}
MODEL_NAME=""
# OpenAI API configuration
OPENAI_API_KEY = ""  
OPENAI_BASE_URL = ""  
TEMPERATURE= 0
MAX_TOKENS=20000  # Can increase output length after extending context
MAX_CHARS=150000  # Maximum character count
LAYER = 3  # callee layer count
# Processing parameter configuration
START_IDX = None                    # Starting idx value, None means process all samples
END_IDX = None                      # Ending idx value (exclusive), None means process to the last one
SAMPLES = None                     # Specify sample idx list, e.g., "0,1,2,3", None means use range
SAMPLES_FILE = ""              # Sample idx file path, None means don't use file
MAX_TOKENS_OVERRIDE = None          # Maximum token count override, None means use MAX_TOKENS above
TIER_OVERRIDE = 'Tier5'                # User tier override, None means use DEFAULT_USER_TIER
CONCURRENCY_OVERRIDE = 1 if TIER_OVERRIDE == 'Free' else 500        # Concurrency override, None means use user tier default

INPUT_JSONL = ""
OUTPUT_DIR = ""+MODEL_NAME.replace("/","_")+"/"

# Prompt 模板
PROMPT_TEMPLATE = """Role: You are an advanced code security auditor.

Carefully study the following code, which includes a Target Function (marked with "// Target Function") and any directly called Callee Functions (marked with "// Callee Function"). Your task is to deeply analyze its logic, data flows, and potential security concerns.

Requirements:
- Return your analysis strictly in valid JSON format only. Do not include any explanations, comments, or Markdown fences.
- Ensure your JSON is detailed, accurate, and useful for code audit purposes.
- All content in the JSON must come exclusively from the Target Function, but you should use the context of Callee Functions to understand the Target Function.
Code:
{code}

Strictly follow this JSON schema in your response:
{{
  "high_level_summary": "Analyze the provided source code segment, understand its structure, data flows, and potential security implications.",
  "key_data_flow_paths": [
    {{
      "description": "Describe a critical data flow path.",
      "path": ["variable1", "variable2", "variable3"]
    }}
  ],
  "sensitive_operations": [
    {{
      "reason": "Explain why this operation is potentially risky."
      "line_content": "The content of the code line.",
    }}
  ],
  "control_flow_hotspots": [
    {{
      "reason": "Explain why this control flow construct is worth attention."
      "line_content": "The content of the code line.",
    }}
  ]
}}

"""