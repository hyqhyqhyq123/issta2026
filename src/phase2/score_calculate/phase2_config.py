"""
Phase 2 configuration file
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

OPENAI_API_KEY = ""  
OPENAI_BASE_URL = ""
MODEL_NAME = ""  
TEMPERATURE = 0
MAX_TOKENS = 100000  # Output token count (consistent with phase1)
MAX_CHARS = 1600000  # Maximum character count (for code truncation)
LAYER = 3

# Processing parameter configuration
START_IDX = None                   # Starting idx value, None means process all samples
END_IDX = None                     # Ending idx value (exclusive), None means process to the last one
SAMPLES = None                      # Specify sample idx list, e.g., "0,1,2,3", None means use range
SAMPLES_FILE = None                 # Sample idx file path, None means don't use file
SAMPLES_FILE = ""               # Sample idx file path, None means don't use file
MAX_TOKENS_OVERRIDE = None          # Maximum token count override, None means use MAX_TOKENS above
TIER_OVERRIDE = 'Tier5'             # User tier override, None means use DEFAULT_USER_TIER
CONCURRENCY_OVERRIDE = 1 if TIER_OVERRIDE == 'Free' else 500        # Concurrency override, None means use user tier default

# Data paths
INPUT_JSONL = ""
SUMMARY_FILE = ""
OUTPUT_DIR = ""+MODEL_NAME+"/"
# Prompt template
PROMPT_TEMPLATE = """Role: You are a code security audit expert.
Task:
1. The Code Context includes a Target Function(marked with "// Target Function") and its callees(marked with "// Callee Function").
2. ONLY identify high-risk lines within the Target Function.
3. Use the provided code auditing report to focus on critical data flows and
   security-sensitive operations.
Output requirements (JSON format):
{{ "risk_lines": ["memcpy(dst, src, size);"] }}
Code: {code}
Code audit report: {summary}
"""

PROMPT_TEMPLATE2 = """Role: You are a code security auditing expert specializing in vulnerability detection.

Code:
{code}

Code audit report
{summary}

Task: 
1. The code above contains a Target Function (marked with "// Target Function") and its called functions (marked with "// Callee Function").
2. Please ONLY identify risky lines within the Target Function.
3. For each risky line, return EXACTLY ONE LINE of code (no multi-line blocks).
4. Use the callee functions as context to understand data flow, but DO NOT mark lines from callee functions.
5. Focus on high-confidence vulnerabilities to minimize false positives.

Output requirements (JSON format):
Return a list of potential risk points. For each risk, provide:
- line_content: ONE line of code from the Target Function

Example output:
{{
  "risk_lines": ["memcpy(dst, src, size);"]
}}

**Important**: 
- Only return lines from the Target Function (not from callee functions). 
- If you believe the real risk lies within a callee function, then, instead of returning the suspicious line from the callee, recursively trace up and return the line in the Target Function where this callee function is invoked.
- Each line_content must be a single line (no newlines \\n in the content)
- Remove all comments from line_content (// inline comments and /* */ block comments)
- Return empty list if no high-confidence risks found

Return only valid JSON, no additional text or Markdown."""
