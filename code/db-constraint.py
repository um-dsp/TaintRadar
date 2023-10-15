import sqlparse
import pandas as pd

def isSafe(properties):
    prop = ' '.join(properties)
    safe_types = ['BIT', 'TINYINT', 'BOOL', 'BOOLEAN', 'SMALLINT', 'MEDIUMINT', 'INT', 
                    'INTEGER', 'BIGINT', 'FLOAT', 'DOUBLE', 'DOUBLE PRECISION', 'DECIMAL', 
                    'DEC', 'ENUM', 'SET', 'DATE', 'DATETIME', 'TIMESTAMP', 'TIME', 'YEAR',
                    'numeric', 'smallmoney', 'money', 'real', 'datetime2', 'smalldatetime', 
                    'datetimeoffset', 'uniqueidentifier', 'Byte', 'Long', 'Single', 'Double', 
                    'Currency', 'AutoNumber', 'Yes/No']
    flag = False
    for type in safe_types:
        if type.lower() in prop: 
            flag = True
            break
    return flag

# Replace 'your_database.sql' with the path to your SQL file
sql_file_path = '/home/umd-user/Desktop/navex_project/navex_tests/WeBid/install/sql/dump.sql'

# Read the SQL script
with open(sql_file_path, 'r') as sql_file:
    sql_script = sql_file.read()

# Parse the SQL script
parsed = sqlparse.parse(sql_script)

current_table = None
current_columns = {}
column_name = None
new_column = None
db_schema = {}
column_desc = []
# Iterate through the parsed statements
for statement in parsed:
    # Check if the statement is a CREATE TABLE statement
    if statement.get_type() == 'CREATE':
        current_table = None
        for token in statement.tokens:
            if str(token) == "DATABASE": break
            if isinstance(token, sqlparse.sql.Identifier):
                token_name = token.get_real_name()
                # if token_name not in ["MyISAM", "utf8", "utf8_unicode_ci"]: 
                current_table = token.get_real_name()
                    # print("Table Name", current_table)
    
        # Check if the statement contains a column definition
            if current_table:
                # Extract column name and data type
                if isinstance(token, sqlparse.sql.Parenthesis):
                    for subtoken in token.tokens:
                        if isinstance(subtoken, sqlparse.sql.Identifier):
                            column_name = subtoken.get_real_name()
                            # print("Column Name", column_name)
                        elif isinstance(subtoken, sqlparse.sql.IdentifierList):
                            for item in subtoken.tokens:
                                if isinstance(item, sqlparse.sql.Identifier):
                                    new_column = item.get_real_name()
                                    # print("Column Name", new_column)
                                    current_columns[column_name] = column_desc
                                    column_name = new_column
                                    new_column = None
                                    column_desc = []
                                elif item.ttype not in [sqlparse.tokens.Punctuation, sqlparse.tokens.Newline, sqlparse.tokens.Whitespace, sqlparse.tokens.Punctuation]:
                                    column_desc.append(str(item))
                        elif subtoken.ttype not in [sqlparse.tokens.Punctuation, sqlparse.tokens.Newline, sqlparse.tokens.Whitespace, sqlparse.tokens.Punctuation]:
                            column_desc.append(str(subtoken))
                        elif new_column or subtoken == token.tokens[-1]:
                            current_columns[column_name] = column_desc
                            column_desc = []
                    break
    if current_table:
        db_schema[current_table] = current_columns
        current_columns = {}
        current_table = None

tables = []
columns = []
properties = []
# Print the extracted schema
for table_name, columns_data in db_schema.items():
    print("Table:", table_name)
    for column_name, data_type in columns_data.items():
        print(f"   Column: {column_name}, Properties: {data_type}")
        tables.append(table_name)
        columns.append(column_name)
        properties.append(data_type)

db = pd.DataFrame()
db['Table'] = tables
db['Column'] = columns
db['Properties'] = properties
db['SafeType'] = db['Properties'].apply(isSafe)
db.to_csv('database.csv', index=False, header=False)