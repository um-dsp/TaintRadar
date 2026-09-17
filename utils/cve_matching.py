import os
import re
import sys
import ast
import json
import fnmatch
import argparse
import string
from pathlib import Path

import nltk
import nvdlib
import pandas as pd
from tqdm import tqdm
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize

# Extensions to look at
LANGUAGE_FILE_EXTENSIONS = {
    'php': ['php', 'html', 'js'],
    'java': ['java', 'jsp', 'html', 'js']
}

# Extensions that disqualify a token from being treated as a parameter name
LANGUAGE_FILE_EXCLUSIONS = {
    'php': ['.php', '.html', '.js'],
    'java': ['.java', '.jsp', '.html', '.js']
}

NLTK_RESOURCES = ['stopwords', 'punkt', 'punkt_tab']


def download_nltk_resources() -> None:
    for resource in NLTK_RESOURCES:
        nltk.download(resource)


def build_stopwords() -> list[str]:
    return [word for word in stopwords.words('english') if len(word) > 1]


def build_punctuation() -> set[str]:
    return set(string.punctuation) - {'(', ')', '$'}


def get_files(description: str, language: str) -> list[str]:
    extensions = LANGUAGE_FILE_EXTENSIONS.get(language.lower(), [])
    result = []
    for ext in extensions:
        result += re.findall(rf'\b\w+\.{ext}\b', description, re.IGNORECASE)
    return result


def get_versions(description: str) -> list[str]:
    result = re.findall(r'\d+\.\d+\.\d+', description)
    for version in result:
        description = description.replace(version, '')
    result += re.findall(r'\d+\.\d+', description)
    return result if result else ['0']


def get_vulnerability(description: str) -> str:
    desc = description.lower()
    if "sql" in desc:
        return "SQL Injection"
    elif any(x in desc for x in ["xss", "cross-site scripting", "cross site scripting"]):
        return "XSS"
    elif "file upload" in desc or "file inclusion" in desc:
        return "File Inclusion"
    elif "file access" in desc:
        return "File Access"
    elif "session" in desc:
        return "Session Fixation"
    elif "code injection" in desc:
        return "Code Injection"
    elif "command" in desc:
        return "Command Execution"
    elif "csrf" in desc or "request forgery" in desc:
        return "CSRF"
    return "NA"


def compare_versions(app_version: str, cve_versions: list[str]) -> bool:
    if not app_version or not cve_versions or cve_versions == ['0']:
        return True
    for cve_version in cve_versions:
        v1 = list(map(int, app_version.split('.')))
        v2 = list(map(int, cve_version.split('.')))
        size = min(len(v1), len(v2))
        if v2[:size] <= v1[:size]:
            return True
    return False


def get_parameters(description: str, language: str, stop_words: list[str], punctuation: set[str]) -> list[str]:
    words = word_tokenize(description)
    words = [word for word in words if word.lower() not in stop_words and word not in punctuation]

    params = [words[i-1] for i in range(1, len(words)) if words[i] in ["parameter", "parameters"]]
    params += [words[i+2] for i in range(1, len(words)-2) if (words[i-1]=='(' and words[i].isdigit() and words[i+1]==')')]
    params += [words[i+1] for i in range(len(words)-1) if words[i] in ["function", "$"]]

    exclusions = LANGUAGE_FILE_EXCLUSIONS.get(language.lower(), [])
    params = [param.replace('"', '') for param in params if all(ext not in param for ext in exclusions) and '/' not in param]
    return list(set(params))


def get_cve_from_navex(cve_df, file: str) -> str:
    for _, row in cve_df.iterrows():
        if any(file_name in file for file_name in row['filenames']):
            return row['id']
    return 'NA'


def filter_on_files(file_names: list[str], directory_path: str) -> bool:
    if not file_names:
        return True
    for root, _, files in os.walk(directory_path):
        for file_name in file_names:
            if any(fnmatch.fnmatch(f, file_name) for f in files):
                return True
    return False


def substr_as_identifier(main_string: str, substring: str) -> bool:
    pattern = re.compile(rf'{re.escape(substring)}(?![a-zA-Z0-9])')
    return bool(pattern.search(main_string))


def get_files_from_parameters(parameters: list[str], directory_path: str) -> list[str]:
    if not parameters:
        return []
    file_paths = []
    for root, _, files in os.walk(directory_path):
        for filename in files:
            file_path = os.path.join(root, filename)
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    if any(substr_as_identifier(content, param) for param in parameters):
                        file_paths.append(file_path)
            except Exception:
                continue
    return list(set(file_paths))


# Process CVEs into a dataframe
def build_cve_dataframe(app_name: str, app_version: str, language: str, directory_path: str,
                        stop_words: list[str], punctuation: set[str]) -> pd.DataFrame:
    r = nvdlib.searchCVE(keywordSearch=app_name)
    json_formatted_cve = json.dumps(ast.literal_eval(str(r)))
    cve = pd.read_json(json_formatted_cve)

    cve['descriptions'] = cve['descriptions'].apply(lambda descriptions: list(filter(lambda x: x["lang"]=="en", descriptions)))
    cve['descriptions'] = cve['descriptions'].apply(lambda descriptions: descriptions[0]['value'])
    cve['versions'] = cve['descriptions'].apply(get_versions)
    cve['filenames'] = cve['descriptions'].apply(lambda desc: get_files(desc, language))
    cve['cve_vulnerability'] = cve['descriptions'].apply(get_vulnerability)
    cve['parameters'] = cve['descriptions'].apply(lambda desc: get_parameters(desc, language, stop_words, punctuation))
    cve['relevant_version'] = cve['versions'].apply(lambda x: compare_versions(app_version, x))

    cve = cve[cve['cve_vulnerability']!='NA']
    cve = cve[cve['relevant_version']==True]
    cve = cve[cve['filenames'].apply(lambda x: filter_on_files(x, directory_path))]
    cve = cve[cve['parameters'].apply(lambda params: get_files_from_parameters(params, directory_path) != [])]
    cve = cve[cve['filenames'].map(lambda x: x!=[]) | cve['parameters'].map(lambda x: x!=[])]

    return cve.loc[:, ['id', 'cve_vulnerability', 'versions', 'filenames', 'parameters', 'descriptions']]


def as_list(value) -> list:
    return value if type(value)==list else ast.literal_eval(value)


def get_cve_ids(navex_row, cve: pd.DataFrame, matched_cves: list[str]) -> str:
    flag = False
    cve_id = 'NA'
    for _, row in cve.iterrows():
        files = as_list(row['filenames'])
        cve_params = as_list(row['parameters'])
        if not files:
            files = ['']
        for file_name in files:
            if file_name in navex_row.loc['filename'] or file_name=='':
                if row['cve_vulnerability'] == navex_row['vulnerability']:
                    if not cve_params and file_name!='':
                        flag = True
                    else:
                        for param in cve_params:
                            if param.lower().replace('$','') in navex_row['code'].lower() or param == navex_row['methodname']:
                                flag = True
                    if flag:
                        cve_id = row['id']
                        flag = False
                        if cve_id not in matched_cves:
                            matched_cves.append(cve_id)
    return cve_id


def parse_args():
    parser = argparse.ArgumentParser(
        description="Match NVD CVEs against NAVEX vulnerability paths for a given application."
    )
    parser.add_argument(
        "app_name",
        help="Application name, used for the NVD keyword search and the input/output filenames."
    )
    parser.add_argument(
        "--app-version",
        help="Version of the application under analysis; if omitted, CVEs are not filtered by version."
    )
    parser.add_argument(
        "--language",
        default="php",
        choices=sorted(LANGUAGE_FILE_EXTENSIONS),
        help="Source language of the application (default: php)"
    )
    parser.add_argument(
        "--app-dir",
        help="Directory containing the application source (default: applications/<app_name>)"
    )
    parser.add_argument(
        "--extension",
        default="",
        help="Extension/variant tag used in the input and output filenames."
    )
    parser.add_argument(
        "--paths-dir",
        default="output/paths",
        help="Directory holding the NAVEX paths JSON file (default: output/paths)"
    )
    parser.add_argument(
        "--out-dir",
        default="output/cve",
        help="Directory for the CVE and matched-path spreadsheets (default: output/cve)"
    )
    parser.add_argument(
        "--use-cached-cve",
        action="store_true",
        help="Reuse the previously saved CVE spreadsheet instead of querying the NVD."
    )
    return parser.parse_args()


def main():
    args = parse_args()

    app_dir = args.app_dir or os.path.join("applications", args.app_name)
    out_dir = Path(args.out_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    prefix = f"{args.app_name}-{args.extension}"
    cve_file = out_dir / f"{prefix}cve.xlsx"
    navex_file = out_dir / f"{prefix}navex.xlsx"
    paths_file = Path(args.paths_dir).expanduser().resolve() / f"{prefix}output.json"

    download_nltk_resources()
    tqdm.pandas()

    if args.use_cached_cve:
        if not cve_file.is_file():
            print(f"[error] No cached CVE file at {cve_file}", file=sys.stderr)
            sys.exit(1)
        cve = pd.read_excel(cve_file, index_col=0)
    else:
        cve = build_cve_dataframe(
            args.app_name,
            args.app_version,
            args.language,
            app_dir,
            build_stopwords(),
            build_punctuation(),
        )

    print(cve)
    cve.to_excel(cve_file)

    # Join potential CVEs and vulnerability paths matches
    if not paths_file.is_file():
        print(f"[error] No NAVEX paths file at {paths_file}", file=sys.stderr)
        sys.exit(1)

    navex = pd.read_json(paths_file)
    print(navex['vulnerability'].size)

    matched_cves = []
    navex['CVE_id'] = navex.progress_apply(lambda row: get_cve_ids(row, cve, matched_cves), axis=1)
    navex = navex.merge(cve, how='left', left_on='CVE_id', right_on='id').drop(columns=['id', 'cve_vulnerability'])

    print(navex)
    print("Number of exploit matches:", len(matched_cves), "out of #" + str(len(cve['id'])), "CVEs")
    print(matched_cves)
    print(pd.unique(navex['CVE_id']))

    # Save data to excel
    navex.to_excel(navex_file)
    print(f"[ok] Wrote {navex_file}")


if __name__ == "__main__":
    main()
