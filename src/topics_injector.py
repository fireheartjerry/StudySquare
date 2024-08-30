import cs50
import sys
import json

db = cs50.SQL("sqlite:///database.db")

def read_json(file_path):
    with open(file_path, 'r') as file:
        data = json.load(file)
    return data

def write_file(filename, text):
    with open(filename, 'w') as file:
        file.write(text)
    return

def process(input_string):
    parts = input_string.rsplit("_", maxsplit=1)
    if len(parts) == 2 and parts[1].isdigit():
        parts[1] = parts[1].zfill(2)
        return "_".join(parts)
    else:
        return input_string

topic_data = read_json("./static/topics_aime.json")
for val in topic_data:
    pid = val["problem"]
    tag = val["topic"].lower().capitalize()
    if (tag == "Combinatorics" or tag == "Probability"):
        tag = "Counting and probability"
    tid = db.execute("SELECT id FROM tags WHERE name=:name", name=tag)[0]['id']
    db.execute(("INSERT INTO problem_tags (tag_id, problem_id) "
                "VALUES (:tid, :pid)"), tid=tid, pid=pid)
    print(f"Added tag {tag} with id {tid} to problem {pid}.")
