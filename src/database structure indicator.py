import sqlite3
from cs50 import SQL

db=SQL("sqlite:///database.db")

def print_tree(cursor, table_name, level=0):
    """Print table name and its columns in a tree-like structure."""
    indent = '  ' * level
    print(f"{indent}- Table: {table_name}")
    
    # Get the columns of the table
    cursor.execute(f"PRAGMA table_info({table_name});")
    columns = cursor.fetchall()
    
    for column in columns:
        column_name = column[1]
        column_type = column[2]
        column_notnull = column[3]
        column_default = column[4]
        column_pk = column[5]
        print(f"{indent}  - Column: {column_name}, Type: {column_type}, Not Null: {column_notnull}, Default: {column_default}, PK: {column_pk}")
    print()

def main():
    # Connect to SQLite database
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Get all table names
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    
    print("Database Structure:")
    for table in tables:
        table_name = table[0]
        print_tree(cursor, table_name, level=1)
    
    # Close connection
    conn.close()

def prnt():
    ans=db.execute("SELECT problem_id,user_id FROM problem_solved")

    print(ans[0:10])

if __name__ == "__main__":
    main()
    #prnt()
