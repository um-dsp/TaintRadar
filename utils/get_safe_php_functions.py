import os
import re
import json
import csv
import pandas as pd
from tqdm import tqdm
from typing import Dict, List, Any, Optional, Tuple

php_stubs_path = '../phpstorm-stubs/'

def parse_php_stubs(file_path: str) -> List[Dict[str, Any]]:
    """Parse PHP function stubs and extract structured information."""
    
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Extract function blocks (docblock + function signature + attributes)
    function_pattern = r'(/\*\*.*?\*/)\s*(#\[.*?\])?\s*function\s+([a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff]*)\s*\((.*?)\)(?:\s*:\s*([a-zA-Z0-9_|\\\\]+))?\s*\{\s*\}'
    function_matches = re.finditer(function_pattern, content, re.DOTALL)
    
    functions = []
    
    for match in function_matches:
        docblock = match.group(1)
        attributes_block = match.group(2) or ""
        function_name = match.group(3)
        parameters_str = match.group(4)
        return_type = match.group(5) or ""
        
        # Parse docblock
        doc_info = parse_docblock(docblock)
        
        # Parse parameters
        parameters = parse_parameters(parameters_str)
        
        # Parse attributes
        attributes = parse_attributes(attributes_block)
        
        # Create function info dictionary
        function_info = {
            "name": function_name,
            "parameters": parameters,
            "return_type": return_type.split("|"),
            "doc_comment": doc_info,
            "attributes": attributes
        }
        
        functions.append(function_info)
    
    return functions

def parse_docblock(docblock: str) -> Dict[str, Any]:
    """Parse PHP docblock and extract structured information."""
    
    # Extract description (first line after /**) 
    description_match = re.search(r'/\*\*\s*\n\s*\*\s*([^\n@]+)', docblock)
    description = description_match.group(1).strip() if description_match else ""
    
    # Extract @link
    link_match = re.search(r'@link\s+([^\s\n]+)', docblock)
    link = link_match.group(1) if link_match else ""
    
    # Extract @param tags
    param_pattern = r'@param\s+([^\s]+)\s+\$([^\s]+)(?:\s+(?:\[optional\])?)?\s*(?:<p>)?(.*?)(?:</p>)?(?=\s*\*\s*(?:@|\*/))'
    param_matches = re.finditer(param_pattern, docblock, re.DOTALL)
    
    params = []
    for param_match in param_matches:
        param_type = param_match.group(1)
        param_name = param_match.group(2)
        param_desc = re.sub(r'\s*\*\s*', ' ', param_match.group(3)).strip()
        
        params.append({
            "name": param_name,
            "type": param_type,
            "description": param_desc
        })
    
    # Extract @return tag
    return_pattern = r'@return\s+([^\s]+)\s*(?:<p>)?(.*?)(?:</p>)?(?=\s*\*\s*(?:@|\*/))'
    return_match = re.search(return_pattern, docblock, re.DOTALL)
    
    return_info = {}
    if return_match:
        return_type = return_match.group(1)
        return_desc = re.sub(r'\s*\*\s*', ' ', return_match.group(2)).strip()
        return_info = {
            "type": return_type.split("|"),
            "description": return_desc
        }
    
    return {
        "description": description,
        "link": link,
        "params": params,
        "return": return_info
    }

def parse_parameters(parameters_str: str) -> List[Dict[str, Any]]:
    """Parse PHP function parameters."""
    
    if not parameters_str.strip():
        return []
    
    # Split by commas, but respect nested structures
    params = []
    current_param = ""
    bracket_depth = 0
    
    for char in parameters_str:
        if char == ',' and bracket_depth == 0:
            params.append(current_param.strip())
            current_param = ""
        else:
            current_param += char
            if char in '[{(':
                bracket_depth += 1
            elif char in ']})':
                bracket_depth -= 1
    
    if current_param.strip():
        params.append(current_param.strip())
    
    # Parse each parameter
    parsed_params = []
    for param in params:
        param_info = parse_parameter(param)
        parsed_params.append(param_info)
    
    return parsed_params

def parse_parameter(param_str: str) -> Dict[str, Any]:
    """Parse a single PHP function parameter."""
    
    # Check for variadic
    is_variadic = '...' in param_str
    if is_variadic:
        param_str = param_str.replace('...', '')
    
    # Check for reference
    is_reference = '&' in param_str
    if is_reference:
        param_str = param_str.replace('&', '')
    
    # Extract type hint
    type_hint = None
    type_match = re.match(r'([a-zA-Z0-9_|\\<>\[\]]+)\s+', param_str)
    if type_match:
        type_hint = type_match.group(1)
        param_str = param_str[len(type_match.group(0)):]
    
    # Extract parameter name
    name_match = re.match(r'\$([a-zA-Z0-9_]+)', param_str)
    name = name_match.group(1) if name_match else ""
    
    # Extract default value
    default_value = None
    default_match = re.search(r'=\s*(.+)$', param_str)
    if default_match:
        default_value = default_match.group(1).strip()
    
    return {
        "name": name,
        "type": type_hint,
        "default": default_value,
        "is_reference": is_reference,
        "is_variadic": is_variadic
    }

def parse_attributes(attributes_block: str) -> List[str]:
    """Parse PHP 8 attributes."""
    
    if not attributes_block:
        return []
    
    # Extract attribute names
    attr_pattern = r'#\[\s*([a-zA-Z0-9_\\]+)(?:\(.*?\))?\s*\]'
    attr_matches = re.finditer(attr_pattern, attributes_block)
    
    attributes = []
    for attr_match in attr_matches:
        attr_name = attr_match.group(1)
        attributes.append(attr_name)
    
    return attributes

def save_as_json(functions: List[Dict[str, Any]], output_file: str) -> None:
    """Save extracted function data as JSON."""
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(functions, f, indent=2)

def save_as_csv(functions: List[Dict[str, Any]], output_file: str) -> None:
    """Save extracted function data as CSV."""
    
    fieldnames = ['name', 'return_type', 'parameters', 'description', 'link', 'attributes']
    
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for func in functions:
            # Format parameters for CSV
            params_str = ', '.join([
                f"{p.get('type', '')} {'&' if p.get('is_reference') else ''}{'...' if p.get('is_variadic') else ''}${p['name']}{' = ' + p['default'] if p.get('default') else ''}"
                for p in func['parameters']
            ])
            
            # Format attributes for CSV
            attrs_str = ', '.join(func['attributes'])
            
            writer.writerow({
                'name': func['name'],
                'return_type': func['return_type'],
                'parameters': params_str,
                'description': func['doc_comment']['description'],
                'link': func['doc_comment']['link'],
                'attributes': attrs_str
            })
            
functions = []
for directory in tqdm(os.listdir(php_stubs_path), desc="Iterating through PHP Storm stubs directories..."):
    if os.path.isdir(os.path.join(php_stubs_path, directory)):
        for file in os.listdir(os.path.join(php_stubs_path, directory)):
            if file.endswith('.php'):
                functions.extend(parse_php_stubs(os.path.join(php_stubs_path, directory, file)))
                
df = pd.json_normalize(functions)
df.fillna({"doc_comment.return.type": df["return_type"]}, inplace=True)
print(f"{len(df['name'].unique())} functions in {df.shape[0]} files")
return_types = df['return_type'].explode().unique()
safe_types = ["int", "integer", "bool", "boolean", "float", "double", "false", "void", "DateTimeImmutable", "DateInterval"]
unsafe_types = [t for t in return_types if t not in safe_types]
df['is_safe'] = df.apply(lambda x: not any(t in x['return_type'] for t in unsafe_types) and not any(t in x['doc_comment.return.type'] for t in unsafe_types), axis=1)

print(f"PHP functions grouped by type safety: {df.groupby('is_safe').size().to_dict()}")

with open("output/safe_functions.json", "w") as f:
    safe_names = df[df["is_safe"]]["name"].unique()
    hash_functions = df[df["name"].str.contains("hash")]["name"].unique()
    json.dump({"type-safe functions": list(safe_names), "hash functions": list(hash_functions)}, f)
    
print("Type-safe and hash functions written to output/safe_functions.json")