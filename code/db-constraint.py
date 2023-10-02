import sqlglot
file = open("/home/umd-user/Desktop/navex_project/navex_tests/SchoolMate_v1.5.4/schoolmate/SchoolMate.sql")
statements = sqlglot.parse(file.read(), read="mysql")
for statement in statements:
    if type(statement) == sqlglot.exp.Create:
        print(statement.arg_key)
        # print(statement, '\n')
        
# for statement in statements:
#     for table in statement.find_all(sqlglot.exp.Table):
        # print(table.name)