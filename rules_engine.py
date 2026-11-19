from utils import logs, db
from datetime import datetime

def get_brute_force_attack_users():
    user_ids = []
    user_timestamps = {}

    for log in logs:
        if log["event_action"] == "auth.login":
            if log["outcome"] == "failure":
                user_id = log["actor"]["user_id"]
                if user_id not in user_timestamps:
                    user_timestamps[user_id] = []
                user_timestamps[user_id].append(log["timestamp"])

    user_timestamps = {
        user_id: sorted(timestamps, reverse=True)
        for user_id, timestamps in user_timestamps.items()
        if len(timestamps) >= 5
    }

    for user_id, timestamps in user_timestamps.items():
        num_of_attempts = 0
        for i in range(len(timestamps) - 1):
            ts1 = datetime.fromisoformat(timestamps[i])
            ts2 = datetime.fromisoformat(timestamps[i + 1])
            diff = ts1 - ts2
            if diff.total_seconds() < 3600:
                num_of_attempts += 1
                if num_of_attempts == 4:
                    user_ids.append(user_id)
                    break
            else:
                num_of_attempts = 0

    if len(user_ids) > 0:
        print(f"Brute-Force Attack Users: {user_ids}")

    return user_ids

def get_compromised_service_account_users():
    user_ids = []

    for log in logs:
        user_id = log["actor"]["user_id"]
        user = db[user_id]
        flag = False
        if "allowed_ips" in user:
            if log["source"]["ip"] not in user["allowed_ips"]:
                flag = True
        if "allowed_resources" in user:
            if log["target_resource"] not in user["allowed_resources"]:
                flag = True
        if flag:
            if user_id not in user_ids:
                user_ids.append(user_id)

    if len(user_ids) > 0:
        print(f"Compromised Service Account Users: {user_ids}")

    return user_ids

def get_geo_violation_users():
    user_ids = []

    for log in logs:
        user_id = log["actor"]["user_id"]
        user = db[user_id]
        if "allowed_countries" in user:
            if log["source"]["geo_country"] not in user["allowed_countries"]:
                if user_id not in user_ids:
                    user_ids.append(user_id)

    if len(user_ids) > 0:
        print(f"Geo-Violation Users: {user_ids}")

    return user_ids