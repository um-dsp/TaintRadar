## Database Constraints

Incorporating database constraints to a vulnerability analysis is a multi-step process:
1. Locate the SQL file that is creating the database schema, include it in the `code/database-constraint.py` Python file and run it. This should output a schema CSV file under the `code\db\schemas` folder with the name of the application.

2. The class `DatabaseConstraint` should now be able to read the schema extracted and infer the type safety of an existing query. You can test it by itself like so:
    ```
    val db = DatabaseConstraint(cpg)
    db.debug()
    ```
    This should output the queries extracted from the CPG divided by type (Select, Insert, Update or Other) and safety (safe or unsafe). The queries are also saved in the `code\db\parsed-queries` CSV file in the format of:
    Type, Raw query, Table, Columns, Variables, Safety (as a boolean)