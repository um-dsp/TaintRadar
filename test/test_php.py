import pytest
import json
from pathlib import Path

BASE_DIR = Path(__file__).parent
EXPECTED_JSON_PATH = BASE_DIR / "sample-expected.json"
CPG_JSON_PATH = BASE_DIR.parent.parent.parent / "standalone-ext" / "output" / "cpg.json"

def load_expected_entries():
    with open(EXPECTED_JSON_PATH, 'r') as f:
        expected_data = json.load(f)
    return [entry for group in expected_data.values() for entry in group]

def load_cpg_entries():
    with open(CPG_JSON_PATH, 'r') as f:
        return json.load(f)

def normalize_code(code):
    """Normalize code for flexible matching by:
    1. Removing parentheses
    2. Normalizing whitespace between function name and arguments
    3. Handling PHP function calls with and without parentheses
    """
    if code is None:
        return None
    
    # First remove all parentheses
    normalized = code.replace('(', ' ').replace(')', '')
    
    # Normalize whitespace (collapse multiple spaces to single space)
    normalized = ' '.join(normalized.split())
    
    return normalized

@pytest.mark.parametrize("expected_entry", load_expected_entries(), 
                         ids=lambda e: f"{e['file']}:L{e['lineNumber']}-{e['code']}")
def test_cpg_matches_expected(expected_entry):
    cpg_entries = load_cpg_entries()
    
    # Only check for fields that exist in the expected entry
    required_keys = ['file', 'lineNumber', 'code']
    if 'SAN_XSS' in expected_entry:
        required_keys.append('SAN_XSS')
    if 'SAN_SQL_Injection' in expected_entry:
        required_keys.append('SAN_SQL_Injection')
    
    match_found = any(
        all(
            key != 'code' and cpg_entry.get(key) == expected_entry[key] or
            key == 'code' and normalize_code(cpg_entry.get(key)) == normalize_code(expected_entry[key])
            for key in required_keys
        )
        for cpg_entry in cpg_entries
    )
    
    # Build error message with only the relevant SAN fields
    san_fields_msg = []
    if 'SAN_XSS' in expected_entry:
        san_fields_msg.append(f"SAN_XSS: {expected_entry['SAN_XSS']}")
    if 'SAN_SQL_Injection' in expected_entry:
        san_fields_msg.append(f"SAN_SQL_Injection: {expected_entry['SAN_SQL_Injection']}")
    
    # Add debug information about normalized code
    normalized_expected = normalize_code(expected_entry['code'])
    
    # Find closest matches for debugging
    closest_matches = []
    for entry in cpg_entries:
        if entry.get('file') == expected_entry['file'] and entry.get('lineNumber') == expected_entry['lineNumber']:
            closest_matches.append({
                'code': entry.get('code'),
                'normalized': normalize_code(entry.get('code'))
            })
    
    assert match_found, (
        f"Missing CPG entry for:\n"
        f"File: {expected_entry['file']}\n"
        f"Line: {expected_entry['lineNumber']}\n"
        f"Code: {expected_entry['code']}\n"
        f"Normalized: {normalized_expected}\n"
        f"Expected {', '.join(san_fields_msg)}\n"
        f"Closest matches: {closest_matches if closest_matches else 'None'}"
    )
