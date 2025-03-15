import os
import json
import pandas as pd
from tqdm import tqdm
from pathlib import Path

new_df = pd.read_csv("sarifs.csv")
new_df = new_df.sample(n=10, random_state=42)
OUT_DIR = Path('/Users/elirizk/Desktop/Texas/2022-05-12-php-test-suite-sqli-v1-0-0')

expected = {}
for _, row in tqdm(new_df.iterrows(), total=new_df.shape[0]):
    if row['message.text'] not in expected:
        expected[row['message.text']] = []
    sanitization_status = "sanitized" if row['is_sanitized'] else "unsanitized"
    line_number = row['physicalLocation.region.startLine']
    output_path = OUT_DIR / row['vulnerability'] / sanitization_status
    with open(output_path / f"{row['properties.id']}.php", 'r') as code:
        file_data = code.read()
        code_line = file_data.splitlines()[line_number - 1].strip()
        os.makedirs(f"php-sample-tests/{row['vulnerability']}/{sanitization_status}", exist_ok=True)
        with open(f"php-sample-tests/{row['vulnerability']}/{sanitization_status}/{row['properties.id']}.php", 'w') as f:
            f.write(file_data)
    properties = {
        "file": f"{row['vulnerability']}/{sanitization_status}/{row['properties.id']}.php",
        "lineNumber": line_number,
        "code": code_line.replace(";", "")
    }
    if row['vulnerability'] == "SQL Injection":
        properties["SAN_SQL_Injection"] = "TRUE" if row['is_sanitized'] else "FALSE"
    else:
        properties["SAN_XSS"] = "TRUE" if row['is_sanitized'] else "FALSE"
    expected[row['message.text']].append(properties)
    
with open('sample-expected.json', 'w') as f:
    json.dump(expected, f, indent=4)
