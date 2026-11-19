from pydantic import BaseModel, Field
from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from langgraph.graph import StateGraph, START, END
from utils import logs, db
import json

class AgentState(BaseModel):
    suspicious_users: list[str]
    quarantined_user: str

class InvestigationResponse(BaseModel):
    reasoning: str = Field(description="Step-by-step analysis checking if the user violated geo-fencing, IP rules, or brute-force patterns.")
    verdict: str = Field(description="Must be strictly 'QUARANTINE' or 'BENIGN'.")

def investigate_flagged_users(state: AgentState) -> dict:
    suspicious_users = state.suspicious_users
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", "You are an expert SOC Cybersecurity Analyst. Your job is to analyze flagged user telemetry and identify hard security violations."),
        (
            "user",
            "User {user_id} is flagged for quarantine.\n"
            "Analyze their profile and activities below.\n"
            "1. Check if their login country matches their allowed_countries.\n"
            "2. Check if their source IP or target resource matches allowed service account rules.\n"
            "3. Check for brute-force patterns.\n\n"
            "Provide your step-by-step reasoning, then give your final verdict as 'QUARANTINE' or 'BENIGN'.\n\n"
            "User Profile:\n\n"
            """
            {user_info}
            """
            "\n\n"
            "Activity Logs:\n\n"
            """
            {user_activities_info}
            """
        )
    ])

    for user_id in list(suspicious_users):
        user = db[user_id]
        activities = [log for log in logs if log["actor"]["user_id"] == user_id]
        formatted_messages = prompt.format_messages(
            user_id=user_id,
            user_info=json.dumps(user),
            user_activities_info=json.dumps(activities)
        )
        structured_llm = llm.with_structured_output(InvestigationResponse)
        response = structured_llm.invoke(formatted_messages)

        print(f"[AI Investigation for {user_id}]")
        print(f"Reasoning: {response.reasoning}")
        print(f"Verdict: {response.verdict}\n")
        
        if response.verdict.upper() != "QUARANTINE":
            suspicious_users.remove(user_id)

    return {
        "suspicious_users": suspicious_users
    }

def suspicious_users_exists(state: AgentState) -> dict:
    if len(state.suspicious_users) > 0:
        return "request_to_quarantine"
    return END

def request_to_quarantine(state: AgentState) -> dict:
    suspicious_users = state.suspicious_users
    quarantined_user = ""

    for user_id in suspicious_users:
        approved = "-"
        while approved.upper() != "Y" and approved.upper() != "N":
            approved = input(f"Quarantining user {user_id}. Do you approve this action (Y/N)? ")
            if approved.upper() == "Y" or approved.upper() == "N":
                if approved.upper() == "Y":
                    quarantined_user = user_id
                else:
                    quarantined_user = "-"
        suspicious_users.remove(user_id)
        break

    return {
        "suspicious_users": suspicious_users,
        "quarantined_user": quarantined_user
    }

def should_quarantine(state: AgentState) -> dict:
    quarantined_user = state.quarantined_user
    if quarantined_user == "":
        return END
    elif quarantined_user == "-":
        return "request_to_quarantine"
    return "quarantine_user"

def quarantine_user(state: AgentState) -> dict:
    quarantined_user = state.quarantined_user

    file_path = "data/iam_directory.json"

    db[quarantined_user]["status"] = "quarantined"

    with open(file_path, "w", encoding="utf-8") as file:
        json.dump(db, file, indent=2)

    return {
        "quarantined_user": ""
    }

llm = ChatOllama(model="qwen2.5:7b-instruct", temperature=0)

workflow = StateGraph(AgentState)

workflow.add_node("investigate_flagged_users", investigate_flagged_users)
workflow.add_node("request_to_quarantine", request_to_quarantine)
workflow.add_node("quarantine_user", quarantine_user)

workflow.add_edge(START, "investigate_flagged_users")
workflow.add_conditional_edges(
    "investigate_flagged_users",
    suspicious_users_exists,
    {
        "request_to_quarantine": "request_to_quarantine",
        END: END
    }
)
workflow.add_conditional_edges(
    "request_to_quarantine",
    should_quarantine,
    {
        "request_to_quarantine": "request_to_quarantine",
        "quarantine_user": "quarantine_user",
        END: END
    }
)
workflow.add_edge("quarantine_user", "request_to_quarantine")

agent = workflow.compile()