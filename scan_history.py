import json
import os
from datetime import datetime

HISTORY_FILE = "scan_history.json"
MAX_HISTORY = 100


def load_history():
    if not os.path.exists(HISTORY_FILE):
        return []

    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)

        if isinstance(data, list):
            return data

        return []

    except (json.JSONDecodeError, OSError):
        return []


def save_scan(result):
    history = load_history()

    classification = str(
        result.get(
            "classification",
            result.get("result", "")
        )
    ).upper()

    record = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "url": result.get("url", ""),
        "classification": classification,
        "result": classification,
        "action": result.get("action", ""),
        "risk_score": result.get("risk_score", 0),
        "ml_score": result.get("ml_score", 0),
        "heuristic_score": result.get("heuristic_score", 0),
        "threat_intelligence_score": result.get(
            "threat_intelligence_score", 0
        )
    }

    history.insert(0, record)
    history = history[:MAX_HISTORY]

    with open(HISTORY_FILE, "w", encoding="utf-8") as file:
        json.dump(history, file, indent=4)


def get_statistics():
    history = load_history()

    total = len(history)
    safe = 0
    warning = 0
    suspicious = 0
    blocked = 0

    for scan in history:

        classification = str(
            scan.get(
                "classification",
                scan.get("result", "")
            )
        ).upper()

        action = str(
            scan.get("action", "")
        ).upper()

        if classification == "SAFE":
            safe += 1

        elif classification == "WARNING":
            warning += 1

        elif classification == "SUSPICIOUS":
            suspicious += 1

        if action == "BLOCK":
            blocked += 1

    return {
        "total": total,
        "safe": safe,
        "warning": warning,
        "suspicious": suspicious,
        "blocked": blocked
    }