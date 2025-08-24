#!/usr/bin/env python3
import argparse
import os
import re
import sys
from pathlib import Path

import pandas as pd
import sqlparse


def isSafe(properties):
    prop = ' '.join(properties)
    safe_types = [
        'BIT', 'TINYINT', 'BOOL', 'BOOLEAN', 'SMALLINT', 'MEDIUMINT', 'INT',
        'INTEGER', 'BIGINT', 'FLOAT', 'DOUBLE', 'DOUBLE PRECISION', 'DECIMAL',
        'DEC', 'ENUM', 'SET', 'DATE', 'DATETIME', 'TIMESTAMP', 'TIME', 'YEAR',
        'numeric', 'smallmoney', 'money', 'real', 'datetime2', 'smalldatetime',
        'datetimeoffset', 'uniqueidentifier', 'Byte', 'Long', 'Single', 'Double',
        'Currency', 'AutoNumber', 'Yes/No'
    ]
    for t in safe_types:
        if t.lower() in prop.lower():
            return True
    return False


def filterDesc(desc):
    filtered_desc = list(map(lambda x: x.lower(), desc))
    if 'constraint' in filtered_desc:
        remove_index = filtered_desc.index('constraint')
    elif 'primary' in filtered_desc:
        remove_index = filtered_desc.index('primary')
    elif 'key' in filtered_desc:
        remove_index = filtered_desc.index('key')
    else:
        remove_index = 0
    if remove_index > 0:
        desc = desc[:remove_index]
    return desc


def sanitize_sql_text(text: str) -> str:
    # Normalize oddities a bit so sqlparse copes better
    return text.replace(' ,', ',').replace('#', '--')


def parse_sql_file(sql_path: Path):
    """
    Returns a list of rows: [(table, column, properties_list, safe_bool), ...]
    """
    with sql_path.open('r', encoding='utf-8', errors='ignore') as f:
        sql_script = sanitize_sql_text(f.read())

    parsed = sqlparse.parse(sql_script)

    current_table = None
    current_columns = {}
    column_name = None
    new_column = None
    db_schema = {}
    column_desc = []

    for statement in parsed:
        if statement.get_type() == 'CREATE':
            current_table = None
            for token in statement.tokens:
                # skip CREATE DATABASE statements
                if str(token).strip().upper() == 'DATABASE':
                    current_table = None
                    break

                # table name
                if isinstance(token, sqlparse.sql.Identifier):
                    token_name = token.get_real_name()
                    current_table = token_name

                # columns list
                if current_table and isinstance(token, sqlparse.sql.Parenthesis):
                    for subtoken in token.tokens:
                        if isinstance(subtoken, sqlparse.sql.Identifier):
                            column_name = subtoken.get_real_name()
                        elif isinstance(subtoken, sqlparse.sql.IdentifierList):
                            for item in subtoken.tokens:
                                if isinstance(item, sqlparse.sql.Identifier):
                                    new_column = item.get_real_name()
                                    new_desc = []
                                    # Build description by finding the piece that includes the column token
                                    for _, element in enumerate(subtoken.value.split(",")):
                                        if new_column in element:
                                            new_desc_raw = element.replace(new_column, '')
                                            new_desc.append(re.sub(r'[^A-Za-z0-9\(\)]+', '', new_desc_raw))
                                            if '' in new_desc:
                                                new_desc.remove('')
                                    column_desc = filterDesc(column_desc)
                                    if column_name:
                                        current_columns[column_name] = column_desc
                                    column_name = new_column
                                    new_column = None
                                    column_desc = new_desc
                                elif item.ttype not in [
                                    sqlparse.tokens.Punctuation,
                                    sqlparse.tokens.Newline,
                                    sqlparse.tokens.Whitespace,
                                ]:
                                    column_desc.append(str(item))
                        elif str(subtoken) == ',':
                            column_desc = filterDesc(column_desc)
                            if column_name:
                                current_columns[column_name] = column_desc
                            new_column = None
                            column_desc = []
                        elif subtoken.ttype not in [
                            sqlparse.tokens.Punctuation,
                            sqlparse.tokens.Newline,
                            sqlparse.tokens.Whitespace,
                        ]:
                            column_desc.append(str(subtoken))
                        elif new_column or subtoken == token.tokens[-1]:
                            column_desc = filterDesc(column_desc)
                            if column_name:
                                current_columns[column_name] = column_desc
                            column_desc = []
                    break  # done with this CREATE TABLE

        if current_table:
            db_schema[current_table] = current_columns
            current_columns = {}
            current_table = None

    rows = []
    for table_name, columns_data in db_schema.items():
        for col_name, props in columns_data.items():
            rows.append((table_name, col_name, props, isSafe(props)))
    return rows


def gather_input_paths(inputs):
    paths = []
    for item in inputs:
        p = Path(item).expanduser().resolve()
        if p.is_dir():
            paths.extend(sorted(p.rglob("*.sql")))
        elif p.is_file():
            paths.append(p)
        else:
            print(f"[warn] Skipping non-existent path: {p}", file=sys.stderr)
    return paths


def main():
    parser = argparse.ArgumentParser(
        description="Extract DB schema (table/columns/types) from SQL files and write CSVs."
    )
    parser.add_argument(
        "inputs",
        nargs="+",
        help="One or more SQL files or directories containing .sql files."
    )
    parser.add_argument(
        "--out-dir",
        default="taint-radar/output/db-schemas",
        help="Output directory for CSV files (default: taint-radar/output/db-schemas)"
    )
    parser.add_argument(
        "--no-header",
        action="store_true",
        help="Write CSVs without a header row (default writes headers)."
    )
    args = parser.parse_args()

    out_dir = Path(args.out_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    sql_paths = gather_input_paths(args.inputs)
    if not sql_paths:
        print("[error] No SQL files found in the provided inputs.", file=sys.stderr)
        sys.exit(1)

    for sql_file in sql_paths:
        try:
            rows = parse_sql_file(sql_file)
            if not rows:
                print(f"[info] No CREATE TABLE statements found in {sql_file.name}")
                continue

            df = pd.DataFrame(rows, columns=["Table", "Column", "Properties", "SafeType"])
            # match your original: Properties list printed as-is; CSV later can be parsed or joined
            # If you prefer a cleaner string: df["Properties"] = df["Properties"].apply(lambda x: " ".join(x))

            # File name: prefer input stem; your example used 'clansphere201144'
            # We'll use the stem of the input file to keep it stable.
            file_stem = sql_file.stem
            out_csv = out_dir / f"{file_stem}-database.csv"
            out_dir1="taint-radar/db-schemas"
            out_csv1=out_dir1 / f"{file_stem}-database.csv"
            df.to_csv(out_csv, index=False, header=not args.no_header)
            df.to_csv(out_csv1, index=False, header=not args.no_header)
            print(f"[ok] Wrote {out_csv}")
        except Exception as e:
            print(f"[error] Failed to process {sql_file}: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
