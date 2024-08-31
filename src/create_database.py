from db import db

db.execute("BEGIN")

db.execute("""CREATE TABLE IF NOT EXISTS 'users' (
                'id' integer PRIMARY KEY NOT NULL,
                'username' varchar(20) NOT NULL UNIQUE,
                'password' varchar(64) NOT NULL,
                'email' varchar(128) UNIQUE,
                'join_date' datetime NOT NULL DEFAULT(0),
                'squares_created' integer NOT NULL DEFAULT(0),
                'squares_joined' integer NOT NULL DEFAULT(0),
                'total_seconds' integer NOT NULL DEFAULT(0),
            );
            CREATE TABLE IF NOT EXISTS 'squares' (
                'id' varchar(64).
                
            );
            """)

db.execute("COMMIT")
