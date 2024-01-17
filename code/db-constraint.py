import sys
import sqlparse
import pandas as pd
import re

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
        if type.lower() in prop.lower(): 
            flag = True
            break
    return flag

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

user_path = "umd-user/Desktop"
if len(sys.argv) > 1 != '': user_path = sys.argv[1]


# Replace 'your_database.sql' with the path to your SQL file
sql_file_paths = []
# sql_file_paths.append(f'/home/{user_path}//navex_project/navex_tests/WeBid/install/sql/dump.sql') # WeBid sql file 
# sql_file_paths.append(f'/home/{user_path}//navex_project/navex_tests/osCommerce/catalog/install/oscommerce.sql') # OsCommerce sql file 
# sql_file_paths.append(f'/home/{user_path}//navex_project/navex_tests/collabtive-31/pgsql.sql') # Collabtive sql file 
# sql_file_paths.append(f'/home/{user_path}//navex_project/navex_tests/faqforge-1.3.2/sql/faqforge.sql') # FAQForge sql file 
# sql_file_paths.append(f'/home/{user_path}//navex_project/navex_tests/gallery-3.0.9/gallery3/installer/install.sql') # Gallery sql file 
# sql_file_paths.append(f'/home/{user_path}//navex_project/navex_tests/hotcrp-2.60/Code/schema.sql') # Hotcrp-2.60 sql file 
# sql_file_paths.append(f'/home/{user_path}//navex_project/navex_tests/hotcrp-2.100/src/schema.sql') # Hotcrp-2.60 sql file 
# sql_file_paths.append(f'/home/{user_path}//navex_project/navex_tests/Joomla_3.7.0-Stable-Full_Package/installation/sql/sqlazure/joomla.sql') # Joomla sql file 
# sql_file_paths.append(f'/home/{user_path}//navex_project/navex_tests/mediawiki/maintenance/mssql/tables.sql') # Mediawiki mssql file 
# sql_file_paths.append(f'/home/{user_path}//navex_project/navex_tests/mediawiki/maintenance/tables.sql') # Mediawiki sql file 
# sql_file_paths.append(f'/home/{user_path}//navex_project/navex_tests/wordpress-6.0/schema.sql') # Wordpress sql file 
# sql_file_paths.append(f'/home/{user_path}//navex_project/navex_tests/wordpress-3.0/schema.sql') # Wordpress sql file 
# sql_file_paths.append(f'/home/{user_path}//navex_project/navex_tests/geccBBlite-0.1/geccBBlite/schema.sql') # geccBBlite sql file 
# sql_file_paths.append(f'/home/{user_path}//navex_project/navex_tests/faqforge-1.3.2/sql/faqforge.sql') # faqforge sql file 
# sql_file_paths.append(f'/home/{user_path}//navex_project/navex_tests/WebChess_0.9.0/schema.sql') # WebChess sql file 
# sql_file_paths.append(f'/home/{user_path}//navex_project/navex_tests/mybloggie214/schema.sql') # MyBloggie sql file 
# sql_file_paths.append(f'/home/{user_path}//navex_project/DVWA/database/create_mssql_db.sql') # DVWA sql file 
# sql_file_paths.append(f'/home/{user_path}//navex_project/navex_tests/phpBB-2.0.23/phpBB2/install/schemas/mysql_schema.sql') # phpBB2 sql file 
# sql_file_paths.append(f'/home/{user_path}//navex_project/navex_tests/phpBB-3.0.11/phpBB3/install/schemas/mysql_41_schema.sql') # phpBB3 sql file 
# sql_file_paths.append(f'/home/{user_path}//navex_project/navex_tests/SchoolMate_v1.5.4/schoolmate/SchoolMate.sql') # SchoolMate sql file 
# sql_file_paths.append(f'/home/{user_path}//navex_project/navex_tests/zen-cart-v1.5.5/zc_install/sql/install/mysql_zencart.sql') # Zencart sql file 
# sql_file_paths.append(f'/home/{user_path}//navex_project/navex_tests/WeBid/install/sql/dump.sql')
# sql_file_paths.append(f'/home/{user_path}//navex_project/navex_tests/WCF/wcfsetup/setup/db/install.sql') # 
# sql_file_paths.append(f'/home/{user_path}//navex_project/navex_tests/woocommerce-3.5.0/tests/e2e-tests/data/e2e-db.sql') # WooCommerce
# sql_file_paths.append(f'/home/{user_path}//navex_project/navex_tests/php-login-system-2.0.1/assets/setup/DBcreation.sql') # PHP Login System
sql_file_paths.append(f'/home/{user_path}//navex_project/navex_tests/openemr-6.0.0/sql/database.sql') # PHP Login System

for sql_file_path in sql_file_paths:
    file_index = sql_file_path.split('/').index('navex_tests')+1
    file_name = sql_file_path.split('/')[file_index]
    sql_file_path.split('/').index('navex_tests')
    # Read the SQL script
    with open(sql_file_path, 'r') as sql_file:
        sql_script = sql_file.read().replace(' ,', ',').replace('#', '--')

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
                if str(token) == 'DATABASE': break
                if isinstance(token, sqlparse.sql.Identifier):
                    token_name = token.get_real_name()
                    # if token_name not in ['MyISAM', 'utf8', 'utf8_unicode_ci']: 
                    current_table = token.get_real_name()
                        # print('Table Name', current_table)
        
            # Check if the statement contains a column definition
                if current_table:
                    # Extract column name and data type
                    if isinstance(token, sqlparse.sql.Parenthesis):
                        for subtoken in token.tokens:
                            if isinstance(subtoken, sqlparse.sql.Identifier):
                                column_name = subtoken.get_real_name()
                                # print('Column Name', column_name)
                            elif isinstance(subtoken, sqlparse.sql.IdentifierList):
                                for item in subtoken.tokens:
                                    if isinstance(item, sqlparse.sql.Identifier):
                                        new_column = item.get_real_name()
                                        new_desc = []
                                        for index, element in enumerate(subtoken.value.split(",")):
                                            if new_column in element:
                                                new_desc_raw = element.replace(new_column, '')
                                                new_desc.append(re.sub(r'[^A-Za-z0-9\(\)]+', '', new_desc_raw))
                                                if ('' in new_desc): new_desc.remove('')
                                        # print('Column Name', new_column)
                                        column_desc = filterDesc(column_desc)
                                        current_columns[column_name] = column_desc
                                        column_name = new_column
                                        new_column = None
                                        column_desc = new_desc
                                    elif item.ttype not in [sqlparse.tokens.Punctuation, sqlparse.tokens.Newline, sqlparse.tokens.Whitespace, sqlparse.tokens.Punctuation]:
                                        column_desc.append(str(item))
                            elif (str(subtoken)==','):
                                column_desc = filterDesc(column_desc)
                                current_columns[column_name] = column_desc
                                new_column = None
                                column_desc = []
                            elif subtoken.ttype not in [sqlparse.tokens.Punctuation, sqlparse.tokens.Newline, sqlparse.tokens.Whitespace, sqlparse.tokens.Punctuation]:
                                column_desc.append(str(subtoken))
                            elif new_column or subtoken == token.tokens[-1]:
                                column_desc = filterDesc(column_desc)
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
        # print('Table:', table_name)
        for column_name, data_type in columns_data.items():
            # print(f'   Column: {column_name}, Properties: {data_type}')
            tables.append(table_name)
            columns.append(column_name)
            properties.append(data_type)
            
    db = pd.DataFrame()
    db['Table'] = tables
    db['Column'] = columns
    db['Properties'] = properties
    db['SafeType'] = list(map(isSafe, properties))
    db.to_csv(f'navex_utils/code/db/schemas/{file_name}-database.csv', index=False, header=False)