import json

with open("data/auth_logs.json", "r", encoding="utf-8") as file:
    logs = json.load(file)

with open("data/iam_directory.json", "r", encoding="utf-8") as file:
    db = json.load(file)