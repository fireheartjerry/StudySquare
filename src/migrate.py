import cs50
import sys
import json
import os

msg = """
Before migrating, please confirm the following:
 - You are on v4.1.x (older version please update to one of these first, new version no migrate necessary)
 - You have write permissions in the current directory
 - The site is shut down. For this migration, maintenance mode is not enough. The site should be completely down.
 - You have made a full database backup. This is a significant migration that can result in unexpected errors.
 
Please note that migration is a one-way operation. Once it is completed, you will not be able to revert to the previous version without a database backup.

Are you sure you wish to migrate? [y/n] """

confirm = input(msg)
if confirm != 'y':
    print('Aborting...')
    sys.exit()

db=cs50.SQL("sqlite:///database.db")
db.execute("BEGIN")

#mental math time taken
import sqlite3

def add_column_with_default(db_path, table_name, new_column_name, default_value):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    existing_columns = get_table_columns(cursor, table_name)
    
    new_column_def = f"{new_column_name} INTEGER DEFAULT {default_value}"
    
    create_table_sql = f"""
    CREATE TABLE IF NOT EXISTS {table_name}_new (
        {', '.join(existing_columns)},
        {new_column_def}
    );
    """
    cursor.execute(create_table_sql)
    
    columns_names = ', '.join([col.split(' ')[0] for col in existing_columns])
    insert_sql = f"""
    INSERT INTO {table_name}_new ({columns_names})
    SELECT {columns_names}
    FROM {table_name};
    """
    cursor.execute(insert_sql)
    
    cursor.execute(f"DROP TABLE {table_name};")
    
    cursor.execute(f"ALTER TABLE {table_name}_new RENAME TO {table_name};")
    
    conn.commit()
    conn.close()

def get_table_columns(cursor, table_name):
    """Get column names and types of the table."""
    cursor.execute(f"PRAGMA table_info({table_name});")
    columns = cursor.fetchall()
    return [f"{column[1]} {column[2]}" for column in columns]

add_column_with_default('database.db', 'users', 'time_taken_on_mental_math', 10000)

#problem time taken
def change():
    ans=db.execute("SELECT problem_id,user_id FROM problem_solved")
    db.execute("ALTER TABLE problem_solved ADD COLUMN time_taken INTEGER")

    for i in ans:
        i['time_taken']=-1

    for i in ans:
        db.execute("""UPDATE problem_solved
                   SET time_taken=:time_taken
                   WHERE problem_id=:problem_id AND user_id=:user_id
                   """,
                   time_taken=i['time_taken'],
                   problem_id=i['problem_id'],
                   user_id=i['user_id'])

change()

#unsolved problems start time

db.execute("""CREATE TABLE IF NOT EXISTS unfinished_problems (
    problem_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    start_time TEXT NOT NULL)""")

#whole text search database

if not os.path.exists("problemdatabase.db"):
    open("problemdatabase.db","w").close()

# problem_db=cs50.SQL("sqlite:///problemdatabase.db")

# problem_db.execute("""
#     CREATE TABLE problems(
#     problem_id TEXT NOT NULL,
#     keyword TEXT NOT NULL,
#     UNIQUE(problem_id,keyword)
#     )""")

# problem_db.execute("""
#     CREATE INDEX IF NOT EXISTS idx_problem_id ON problems(problem_id)""")

# problem_db.execute("""
#     CREATE INDEX IF NOT EXISTS idx_keyword ON problems(keyword)""")

# problems=db.execute("SELECT id FROM problems")

# for i in problems:
#     try:
#         with open("metadata/problems/"+i['id']+"/description.md") as file:
#             content=file.readlines()
#             file.close()
#     except:
#         print("problem markdown file missing:",i['id'])
#         print("please restore the markdown file, delete problemdatabase.db, revert to the old version of database.db and rerun this program")
#         continue

#     words=[]
#     for j in content:
#         cache=j.split(' ')
#         for k in cache:
#             words.append(k.lower())

#     for j in words:
#         try:
#             problem_db.execute("INSERT INTO problems (problem_id,keyword) values (:pid,:word)",
#                                 pid=i['id'],word=j)
#         except:
#             pass


"""answers = json.load(open("/root/TopsOJ/src/static/fermat_answers.json"))
def convert(pid):
    # 98 fermat p05
    year, _, problem = pid.split("_")
    year = "19"+year if year[0] == '9' else "20"+year
    problem = int(problem[1:])
    return f"{year} Fermat Problem {problem}"

def get_answer(pid):
    year, _, problem = pid.split("_")
    return answers[year+'_'+problem[1:]]

def write_file(filename, text):
    with open(filename, 'w') as file:
        file.write(text)
    return"""
    
"""directory = "static/problemlists/amc8"
for root, dirs, files in os.walk(directory):
    for file in files:
        if "amc8" not in file:
            file_path = os.path.join(root, file)
            os.remove(file_path)
            
directory = "static/problemlists/amc10"
for root, dirs, files in os.walk(directory):
    for file in files:
        if "amc10" not in file:
            file_path = os.path.join(root, file)
            os.remove(file_path)

directory = "static/problemlists/amc12"
for root, dirs, files in os.walk(directory):
    for file in files:
        if "amc12" not in file:
            file_path = os.path.join(root, file)
            os.remove(file_path)"""

# db.execute("BEGIN")

# RAN LOCALLY
# db.execute("ALTER TABLE users ADD COLUMN 'admin' boolean NOT NULL DEFAULT(0)")
# db.execute("UPDATE users SET admin = 1 WHERE id IN (SELECT user_id FROM user_perms WHERE perm_id IN (0, 1));")

"""tag_ids = {
    "Algebra" : 1,
    "Geometry" : 3,
    "Number theory" : 6,
    "Counting and probability" : 9,
    "Trigonometry" : 18,
}
tag_data = json.load(open("amc12_tags.json"))
for row in tag_data:
    db.execute(("INSERT INTO problem_tags (tag_id, problem_id) VALUES (:tid, :pid)"), tid=tag_ids[row["category"]], pid=row["id"])"""


""" Enhance attribution
for year in tqdm(range(1997, 2024), desc="Adding Fermat Problems"):
    for file in os.listdir(f"static/fermat/{year}"):
        pid = file[:-4]
        print(pid, year)
        problem_number = int(pid.split('_')[-1][1:])
        points = 0
        title = convert(pid)
        answer = get_answer(pid)
        description_md = f'<img src="/static/fermat/{year}/{file}" width="800px">\n\nIf there are no answer choices shown, enter a numerical answer.\n\n___\n\n**Full credit to this problem is given to the [CEMC](https://cemc.uwaterloo.ca/), you may view all fermat contests [here](https://www.cemc.uwaterloo.ca/contests/past_contests.html#pcf).**'
        description_html = f'<img src="/static/fermat/{year}/{file}" width="800px"><p>If there are no answer choices shown, enter a numerical answer.</p><hr><p><b>Full credit to this problem is given to the <a href="https://cemc.uwaterloo.ca/">CEMC</a>, you may view all fermat contests <a href="https://www.cemc.uwaterloo.ca/contests/past_contests.html#pcf">here</a>.</b></p>'
        if (problem_number <= 15):
            points = 1
        elif (problem_number <= 20):
            points = 2
        else:
            points = 3
        os.makedirs('metadata/problems/' + pid, exist_ok=True)
        write_file('metadata/problems/' + pid + '/description.md', description_md)
        write_file('metadata/problems/' + pid + '/description.html', description_html)
        write_file('metadata/problems/' + pid + '/hints.md', "")
        write_file('metadata/problems/' + pid + '/hints.html', "")
        open('metadata/problems/' + pid + '/editorial.md', 'w').close()
        db.execute(("INSERT INTO problems (id, name, point_value, category, flag, draft, "
                    "flag_hint, instanced) VALUES (:id, :name, :point_value, :category, "
                    ":flag, :draft, :fhint, :inst)"),
                id=pid, name=title, point_value=points, category="Fermat",
                flag=answer, draft=0, fhint="", inst=False)
"""
db.execute("COMMIT")

print('Migration completed.')
