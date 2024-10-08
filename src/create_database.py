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
                'total_seconds' integer NOT NULL DEFAULT(0)
            );""")

db.execute("""CREATE TABLE IF NOT EXISTS 'squares' (
                'id' varchar(6) NOT NULL UNIQUE,
                'name' varchar(256) NOT NULL,
                'creator' integer NOT NULL,
                'create_date' datetime NOT NULL DEFAULT(0),
                'preview' varchar(200),
                'description' varchar(1000),
                'public' boolean NOT NULL DEFAULT(1),
                'members' integer NOT NULL DEFAULT(1),
                'meeting_code' varchar(64) NOT NULL,
                'image_type' integer NOT NULL,
                'topic' varchar(64) NOT NULL
            );""")

db.execute("""CREATE TABLE IF NOT EXISTS 'square_members' (
                'id' integer PRIMARY KEY NOT NULL,
                'square_id' varchar(64) NOT NULL,
                'user_id' integer NOT NULL,
                'join_date' datetime NOT NULL
            );""")

db.execute("""CREATE TABLE IF NOT EXISTS 'square_join_log' (
                'id' integer PRIMARY KEY NOT NULL,
                'user_id' integer NOT NULL,
                'square_id' varchar(64) NOT NULL,
                'square_title' varchar(256) NOT NULL,
                'square_creator_username' varchar(20) NOT NULL,
                'session_length' integer NOT NULL DEFAULT(0),
                'date' datetime NOT NULL DEFAULT(datetime('now'))
            );""")

db.execute("""CREATE TABLE IF NOT EXISTS 'hotkeys' (
                'id' integer PRIMARY KEY NOT NULL,
                'user_id' integer NOT NULL,
                'hotkey1' TEXT NOT NULL,
                'hotkey2' TEXT NOT NULL,
                'hotkey3' TEXT NOT NULL,
                'hotkey4' TEXT NOT NULL,
                'hotkey5' TEXT NOT NULL,
                'hotkey6' TEXT NOT NULL
            );""")

db.execute("COMMIT")
