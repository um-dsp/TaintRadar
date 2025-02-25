import pytest
import json
from pathlib import Path

BASE_DIR = Path(__file__).parent
EXPECTED_JSON_PATH = BASE_DIR / "php-tests" / "expected.json"
CPG_JSON_PATH = BASE_DIR.parent.parent / "cpg.json"

def load_expected_entries():
    with open(EXPECTED_JSON_PATH, 'r') as f:
        expected_data = json.load(f)
    return [entry for group in expected_data for entries in group.values() for entry in entries]

def load_cpg_entries():
    with open(CPG_JSON_PATH, 'r') as f:
        return json.load(f)

@pytest.mark.parametrize("expected_entry", load_expected_entries(), 
                         ids=lambda e: f"{e['file']}:L{e['lineNumber']}-{e['code']}")
def test_cpg_matches_expected(expected_entry):
    cpg_entries = load_cpg_entries()
    
    required_keys = ['file', 'lineNumber', 'code', 'SAN_XSS', 'SAN_SQL_Injection']
    match_found = any(
        all(cpg_entry.get(key) == expected_entry[key] for key in required_keys)
        for cpg_entry in cpg_entries
    )
    
    assert match_found, (
        f"Missing CPG entry for:\n"
        f"File: {expected_entry['file']}\n"
        f"Line: {expected_entry['lineNumber']}\n"
        f"Code: {expected_entry['code']}\n"
        f"Expected SAN_XSS: {expected_entry['SAN_XSS']}, SAN_SQL_Injection: {expected_entry['SAN_SQL_Injection']}"
    )
