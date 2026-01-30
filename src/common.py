#!/usr/bin/env python3
"""
Common utility functions
Contains reusable features like truncation, retry, etc.
"""
import json
import time
import logging
from typing import Callable, Any, TypeVar, Dict, List

logger = logging.getLogger(__name__)

T = TypeVar('T')

# ============================================================================
# Text truncation utilities
# ============================================================================

def truncate_text(text: str, max_chars: int = 20000) -> str:
    """
    Truncate text to specified character count
    
    Args:
        text: Original text
        max_chars: Maximum character count
    
    Returns:
        Truncated text
    """
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n... [truncated]"


def format_code_input(item: dict, max_chars: int = 20000) -> str:
    """
    Format code input, including summary, target function and callee functions
    Total length limited to max_chars characters
    
    Args:
        item: Dictionary containing func, summary, callee fields
        max_chars: Maximum character count
    
    Returns:
        Formatted code input text
    """
    parts = []
    current_length = 0
    
    # 1. Summary
    if 'summary' in item and item['summary']:
        summary_text = json.dumps(item['summary'], ensure_ascii=False, indent=2)
        summary_section = f"## Code Summary:\n{summary_text}\n"
        parts.append(summary_section)
        current_length += len(summary_section)
    
    # 2. Target Function (prioritize retention)
    if 'func' in item:
        func_text = item['func']
        remaining = max_chars - current_length
        if len(func_text) > remaining:
            func_text = truncate_text(func_text, remaining - 10)
        target_section = f"## Target Function:\n```c\n{func_text}\n```\n"
        parts.append(target_section)
        current_length += len(target_section)
    
    # 3. Callee Functions (add based on remaining space)
    if 'callee' in item and item['callee']:
        parts.append("## Callee Functions:\n")
        current_length += len("## Callee Functions:\n")
        
        for i, callee in enumerate(item['callee'], 1):
            func_name = callee.get('func_name', 'unknown')
            func_str = callee.get('func_str', '')
            layer = callee.get('layer', '?')
            
            # Check if there's still space
            remaining = max_chars - current_length
            if remaining < 10:
                parts.append("... [more callee functions truncated]\n")
                break
            
            # Truncate overly long callee function
            if len(func_str) > remaining - 10:
                func_str = truncate_text(func_str, remaining - 10)
            
            callee_section = f"### {i}. {func_name} (Layer {layer}):\n```c\n{func_str}\n```\n"
            parts.append(callee_section)
            current_length += len(callee_section)
    
    result = '\n'.join(parts)
    
    # Final safety check: if still exceeds, force truncation
    if len(result) > max_chars:
        result = result[:max_chars] + "\n... [final truncation]"
    
    return result


# ============================================================================
# Retry mechanism
# ============================================================================

def retry_with_backoff(
    func: Callable[..., T],
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    exceptions: tuple = (Exception,),
    on_retry: Callable[[int, Exception], None] = None
) -> T:
    """
    Retry mechanism with exponential backoff
    
    Args:
        func: Function to execute
        max_retries: Maximum retry count
        base_delay: Base delay time (seconds)
        max_delay: Maximum delay time (seconds)
        exceptions: Exception types to catch
        on_retry: Callback function on retry (attempt, exception) -> None
    
    Returns:
        Function execution result
        
    Raises:
        Last failed exception
    
    Example:
        >>> def api_call():
        ...     return requests.get("http://api.example.com")
        >>> 
        >>> result = retry_with_backoff(
        ...     api_call,
        ...     max_retries=3,
        ...     exceptions=(requests.RequestException,)
        ... )
    """
    last_exception = None
    
    for attempt in range(max_retries):
        try:
            return func()
        except exceptions as e:
            last_exception = e
            
            if attempt < max_retries - 1:
                # Calculate delay time (exponential backoff)
                delay = min(base_delay * (2 ** attempt), max_delay)
                
                # Call retry callback
                if on_retry:
                    on_retry(attempt + 1, e)
                else:
                    logger.warning(
                        f"Attempt {attempt + 1}/{max_retries} failed: {str(e)[:100]}. "
                        f"Retrying in {delay:.1f}s..."
                    )
                
                time.sleep(delay)
            else:
                logger.error(
                    f"All {max_retries} attempts failed. Last error: {str(e)[:200]}"
                )
    
    # All retries failed, raise last exception
    raise last_exception


def retry_on_error(max_retries: int = 3, base_delay: float = 1.0):
    """
    Decorator version of retry mechanism
    
    Args:
        max_retries: Maximum retry count
        base_delay: Base delay time (seconds)
    
    Example:
        >>> @retry_on_error(max_retries=3, base_delay=2.0)
        ... def unstable_function():
        ...     # 可能失败的操作
        ...     return api_call()
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        def wrapper(*args, **kwargs) -> T:
            return retry_with_backoff(
                lambda: func(*args, **kwargs),
                max_retries=max_retries,
                base_delay=base_delay
            )
        return wrapper
    return decorator


# ============================================================================
# LLM calling utilities
# ============================================================================

def call_llm_with_retry(
    client,
    messages: List[Dict[str, str]],
    model: str,
    temperature: float = 0.0,
    max_tokens: int = 1024,
    max_retries: int = 3,
    **kwargs
) -> str:
    """
    LLM call with retry mechanism
    
    Args:
        client: OpenAI client
        messages: Message list
        model: Model name
        temperature: Temperature parameter
        max_tokens: Maximum token count
        max_retries: Maximum retry count
        **kwargs: Other parameters
    
    Returns:
        Model response content
        
    Example:
        >>> from openai import OpenAI
        >>> client = OpenAI(api_key="...", base_url="...")
        >>> 
        >>> messages = [
        ...     {"role": "system", "content": "You are a helpful assistant."},
        ...     {"role": "user", "content": "Hello!"}
        ... ]
        >>> 
        >>> response = call_llm_with_retry(
        ...     client=client,
        ...     messages=messages,
        ...     model="gpt-3.5-turbo",
        ...     max_retries=3
        ... )
    """
    def make_request():
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            **kwargs
        )
        
        if not response or not response.choices or not response.choices[0].message.content:
            raise ValueError(f"Empty response from LLM: {response}")
        
        return response.choices[0].message.content
    
    return retry_with_backoff(
        make_request,
        max_retries=max_retries,
        base_delay=2.0
    )


# ============================================================================
# JSON parsing utilities
# ============================================================================

def extract_json_from_text(text: str) -> dict:
    """
    Extract JSON from text (handles mixed reasoning text)
    
    Args:
        text: Text that may contain JSON
    
    Returns:
        Parsed dictionary
        
    Raises:
        ValueError: If JSON cannot be found or parsed
    """
    # Remove special tags
    for tag in ['<|return|>', '<|end|>', '<|start|>', '<|call|>', '<|channel|>', '<|message|>']:
        text = text.replace(tag, '')
    
    # Extract JSON
    start_idx = text.find('{')
    end_idx = text.rfind('}')
    
    if start_idx == -1 or end_idx == -1 or start_idx >= end_idx:
        raise ValueError(f"Cannot find valid JSON, content: {text[:200]}...")
    
    json_str = text[start_idx:end_idx+1]
    
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        raise ValueError(f"JSON parsing failed: {e}, content: {json_str[:200]}")
    
    if not isinstance(data, dict):
        raise ValueError(f"Returned type is not dict, but: {type(data)}")
    
    # Clean dictionary keys (remove newlines and extra spaces)
    cleaned_data = {}
    for key, value in data.items():
        clean_key = key.replace('\n', '').replace('\r', '').replace('\t', '').strip()
        clean_key = clean_key.strip('"').strip("'")
        cleaned_data[clean_key] = value
    
    return cleaned_data


# ============================================================================
# File operation utilities
# ============================================================================

def load_jsonl(file_path: str) -> List[dict]:
    """
    Load JSONL file
    
    Args:
        file_path: JSONL file path
    
    Returns:
        List of dictionaries
    """
    data = []
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                data.append(json.loads(line))
    return data


def save_jsonl(data: List[dict], file_path: str):
    """
    Save as JSONL file
    
    Args:
        data: List of dictionaries
        file_path: Output file path
    """
    with open(file_path, 'w', encoding='utf-8') as f:
        for item in data:
            f.write(json.dumps(item, ensure_ascii=False) + '\n')


def append_jsonl(item: dict, file_path: str):
    """
    Append a record to JSONL file
    
    Args:
        item: Dictionary to append
        file_path: File path
    """
    with open(file_path, 'a', encoding='utf-8') as f:
        f.write(json.dumps(item, ensure_ascii=False) + '\n')
        f.flush()


# ============================================================================
# Logging utilities
# ============================================================================

def setup_logger(name: str, log_file: str = None, level=logging.INFO) -> logging.Logger:
    """
    Setup logger
    
    Args:
        name: Logger name
        log_file: Log file path (optional)
        level: Log level
    
    Returns:
        Configured logger
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler (if specified)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger


# ============================================================================
# Data processing utilities
# ============================================================================

def clean_dict_keys(data: dict) -> dict:
    """
    Clean dictionary keys (remove newlines and extra spaces)
    
    Args:
        data: Original dictionary
    
    Returns:
        Cleaned dictionary
    """
    cleaned_data = {}
    for key, value in data.items():
        # Remove newlines, tabs and extra spaces from keys
        clean_key = key.replace('\n', '').replace('\r', '').replace('\t', '').strip()
        # If key is wrapped in quotes, remove them
        clean_key = clean_key.strip('"').strip("'")
        cleaned_data[clean_key] = value
    
    return cleaned_data



