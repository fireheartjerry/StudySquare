from cs50 import SQL
import sys
import os

try:
    db = SQL("sqlite:///database.db")
except Exception as e:
    sys.stderr.write(str(e))
    if not os.path.exists("database.db"):
        open("database_test.db", "w").close()
    db = SQL("sqlite:///database_test.db")
