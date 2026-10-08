from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
import uuid
import sqlite3
import json

# ============================================================
# BAYORA SECURITY API
# ============================================================

app = FastAPI(
    title="Bayora Security API",
    description="Adversarial AI Security Testing Platform",
    version="1.0.0"
)

# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=".*",
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# DATABASE
# ============================================================

DATABASE = "bayora.db"


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_database():

    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            incident_id TEXT UNIQUE NOT NULL,

            timestamp TEXT NOT NULL,

            attack_type TEXT NOT NULL,

            prompt TEXT NOT NULL,

            risk_score INTEGER NOT NULL,

            risk_level TEXT NOT NULL,

            decision TEXT NOT NULL,

            matched_indicators TEXT NOT NULL

        )
    """)

    conn.commit()
    conn.close()


# ============================================================
# SECURITY ANALYSIS ENGINE
# ============================================================

def analyze_security(prompt: str, attack_type: str):

    text = prompt.lower()

    indicators = [
        "ignore previous instructions",
        "ignore all previous instructions",
        "system prompt",
        "reveal your instructions",
        "reveal system prompt",
        "bypass safety",
        "bypass security",
        "jailbreak",
        "developer message",
        "forget your rules",
        "disregard previous",
        "override instructions",
        "ignore your rules",
        "show hidden instructions",
        "reveal hidden instructions",
        "hidden prompt",
        "secret instructions",
    ]

    matches = [
        indicator
        for indicator in indicators
        if indicator in text
    ]

    # Base risk
    risk_score = 15

    # Attack type risk
    if attack_type == "Prompt Injection":
        risk_score += 25

    elif attack_type == "Jailbreak":
        risk_score += 35

    elif attack_type == "Sensitive Information":
        risk_score += 30

    elif attack_type == "Malicious Instruction":
        risk_score += 30

    # Indicator risk
    if matches:
        risk_score += min(
            len(matches) * 12,
            45
        )

    # Keep score between 0 and 100
    risk_score = min(
        risk_score,
        100
    )

    # Security decision
    if risk_score >= 70:

        decision = "BLOCK"
        risk_level = "HIGH"

    elif risk_score >= 40:

        decision = "REVIEW"
        risk_level = "MEDIUM"

    else:

        decision = "ALLOW"
        risk_level = "LOW"

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "decision": decision,
        "matched_indicators": matches,
    }


# ============================================================
# ROOT ENDPOINT
# ============================================================

@app.get("/")
def root():

    return {
        "service": "Bayora Security API",
        "status": "operational",
        "version": "1.0.0"
    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health():

    return {
        "status": "healthy",
        "service": "bayora-security-engine"
    }


# ============================================================
# API STATUS
# ============================================================

@app.get("/api/status")
def api_status():

    conn = get_db()

    cursor = conn.execute(
        "SELECT COUNT(*) FROM audit_logs"
    )

    total_tests = cursor.fetchone()[0]

    conn.close()

    return {
        "bayora": "online",
        "security_engine": "active",
        "policy_gateway": "active",
        "audit_logging": "active",
        "total_tests": total_tests,
        "api_version": "1.0.0"
    }


# ============================================================
# SECURITY TEST
# ============================================================

@app.post("/api/security-test")
def security_test(data: dict):

    # --------------------------------------------------------
    # Get prompt
    # --------------------------------------------------------

    prompt = str(
        data.get(
            "prompt",
            ""
        )
    ).strip()

    # --------------------------------------------------------
    # Get attack type
    # --------------------------------------------------------

    attack_type = str(
        data.get(
            "attack_type",
            "Prompt Injection"
        )
    )

    # --------------------------------------------------------
    # Validate prompt
    # --------------------------------------------------------

    if not prompt:

        return {
            "success": False,
            "error": "Security test prompt cannot be empty."
        }

    # --------------------------------------------------------
    # Analyze prompt
    # --------------------------------------------------------

    analysis = analyze_security(
        prompt,
        attack_type
    )

    # --------------------------------------------------------
    # Generate incident ID
    # --------------------------------------------------------

    incident_id = (
        "BY-"
        + str(
            uuid.uuid4()
        ).replace(
            "-",
            ""
        )[:8].upper()
    )

    # --------------------------------------------------------
    # Timestamp
    # --------------------------------------------------------

    timestamp = datetime.now().isoformat()

    # --------------------------------------------------------
    # Store event in SQLite
    # --------------------------------------------------------

    conn = get_db()

    conn.execute(
        """
        INSERT INTO audit_logs (
            incident_id,
            timestamp,
            attack_type,
            prompt,
            risk_score,
            risk_level,
            decision,
            matched_indicators
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            incident_id,
            timestamp,
            attack_type,
            prompt,
            analysis["risk_score"],
            analysis["risk_level"],
            analysis["decision"],
            json.dumps(
                analysis["matched_indicators"]
            )
        )
    )

    conn.commit()
    conn.close()

    # --------------------------------------------------------
    # Security message
    # --------------------------------------------------------

    if analysis["decision"] == "BLOCK":

        message = (
            "Request blocked by Bayora policy."
        )

    elif analysis["decision"] == "REVIEW":

        message = (
            "Request flagged for security review."
        )

    else:

        message = (
            "Request passed Bayora policy evaluation."
        )

    # --------------------------------------------------------
    # Return result
    # --------------------------------------------------------

    return {

        "success": True,

        "incident_id": incident_id,

        "timestamp": timestamp,

        "attack_type": attack_type,

        "risk_score": analysis[
            "risk_score"
        ],

        "risk_level": analysis[
            "risk_level"
        ],

        "decision": analysis[
            "decision"
        ],

        "matched_indicators": analysis[
            "matched_indicators"
        ],

        "message": message,
    }


# ============================================================
# AUDIT LOGS
# ============================================================

@app.get("/api/audit-logs")
def get_audit_logs():

    conn = get_db()

    cursor = conn.execute(
        """
        SELECT
            incident_id,
            timestamp,
            attack_type,
            prompt,
            risk_score,
            risk_level,
            decision,
            matched_indicators
        FROM audit_logs
        ORDER BY id DESC
        LIMIT 50
        """
    )

    rows = cursor.fetchall()

    conn.close()

    logs = []

    for row in rows:

        logs.append({

            "incident_id": row["incident_id"],

            "timestamp": row["timestamp"],

            "attack_type": row["attack_type"],

            "prompt": row["prompt"],

            "risk_score": row["risk_score"],

            "risk_level": row["risk_level"],

            "decision": row["decision"],

            "matched_indicators": json.loads(
                row["matched_indicators"]
            ),
        })

    return {

        "success": True,

        "count": len(logs),

        "logs": logs
    }


# ============================================================
# DELETE / CLEAR AUDIT LOGS
# ============================================================

@app.delete("/api/audit-logs")
def clear_audit_logs():

    conn = get_db()

    conn.execute(
        "DELETE FROM audit_logs"
    )

    conn.commit()

    conn.close()

    return {

        "success": True,

        "message": "All audit logs cleared.",

        "count": 0
    }


# ============================================================
# STARTUP
# ============================================================

@app.on_event("startup")
def startup_event():

    init_database()

    print("")
    print("==========================================")
    print("        BAYORA SECURITY ENGINE")
    print("==========================================")
    print("Security Engine : ACTIVE")
    print("Policy Gateway  : ACTIVE")
    print("Audit Logging   : ACTIVE")
    print("Database        : SQLite")
    print("API Version     : 1.0.0")
    print("==========================================")
    print("")