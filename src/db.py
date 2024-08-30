from cs50 import SQL
import sys
import os

try:
    db = SQL("sqlite:///database.db")
    problem_db = SQL("sqlite:///problemdatabase.db")
except Exception as e:  # when testing
    sys.stderr.write(str(e))
    if not os.path.exists("database.db"):
        open("database_test.db", "w").close()
    if not os.path.exists("problemdatabase.db"):
        open("problemdatabase.db","w").close()
    problem_db = SQL("sqlite:///problemdatabase.db")
    db = SQL("sqlite:///database_test.db")
