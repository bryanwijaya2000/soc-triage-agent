from rules_engine import get_brute_force_attack_users, get_compromised_service_account_users, get_geo_violation_users
from agent import agent

def run_pipeline():
    print()

    flagged_users = get_brute_force_attack_users() + get_compromised_service_account_users() + get_geo_violation_users()
    flagged_users = list(set(flagged_users))

    print(f"\nFlagged Users: {flagged_users}\n")

    agent.invoke({
        "suspicious_users": flagged_users,
        "quarantined_user": ""
    })

run_pipeline()