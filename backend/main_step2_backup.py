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
    version="2.0.0"
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

            matched_indicators TEXT NOT NULL,

            detected_threats TEXT NOT NULL DEFAULT '[]',

            primary_threat TEXT NOT NULL DEFAULT 'No Threat Detected',

            threat_count INTEGER NOT NULL DEFAULT 0,

            policy_id TEXT NOT NULL DEFAULT 'AI-SAFETY-001',

            policy_reason TEXT NOT NULL DEFAULT 'Policy evaluation completed.',

            action_taken TEXT NOT NULL DEFAULT 'NONE',

            intercepted INTEGER NOT NULL DEFAULT 0
        )
    """)

    # ========================================================
    # DATABASE UPGRADE
    # ========================================================

    existing_columns = [
        row["name"]
        for row in conn.execute(
            "PRAGMA table_info(audit_logs)"
        ).fetchall()
    ]

    new_columns = {

        "detected_threats":
            "TEXT NOT NULL DEFAULT '[]'",

        "primary_threat":
            "TEXT NOT NULL DEFAULT 'No Threat Detected'",

        "threat_count":
            "INTEGER NOT NULL DEFAULT 0",

        "policy_id":
            "TEXT NOT NULL DEFAULT 'AI-SAFETY-001'",

        "policy_reason":
            "TEXT NOT NULL DEFAULT 'Policy evaluation completed.'",

        "action_taken":
            "TEXT NOT NULL DEFAULT 'NONE'",

        "intercepted":
            "INTEGER NOT NULL DEFAULT 0",
    }

    for column, definition in new_columns.items():

        if column not in existing_columns:

            conn.execute(
                f"""
                ALTER TABLE audit_logs
                ADD COLUMN {column} {definition}
                """
            )

    conn.commit()
    conn.close()


# ============================================================
# THREAT DETECTION ENGINE
# ============================================================

def analyze_security(prompt: str, attack_type: str):

    text = prompt.lower()

    threat_signatures = {

        "Prompt Injection": [
            "ignore previous instructions",
            "ignore all previous instructions",
            "disregard previous instructions",
            "override instructions",
            "ignore your rules",
            "forget your rules",
        ],

        "System Prompt Extraction": [
            "system prompt",
            "reveal your instructions",
            "reveal system prompt",
            "show hidden instructions",
            "reveal hidden instructions",
            "hidden prompt",
            "secret instructions",
        ],

        "Jailbreak": [
            "jailbreak",
            "bypass safety",
            "bypass security",
            "disable safety",
            "remove restrictions",
            "act without restrictions",
            "ignore safety rules",
        ],

        "Role Manipulation": [
            "pretend you are",
            "act as an unrestricted",
            "you are now",
            "roleplay as",
            "developer mode",
            "admin mode",
            "unrestricted mode",
        ],

        "Sensitive Information": [
            "confidential information",
            "private information",
            "secret data",
            "password",
            "api key",
            "access token",
            "credentials",
        ],

        "Data Exfiltration": [
            "send the data",
            "export the data",
            "copy the data",
            "extract the data",
            "leak the data",
            "transfer the data",
            "upload the data",
        ],

        "Malicious Instruction": [
            "execute this command",
            "run this command",
            "delete all files",
            "destroy the database",
            "disable security",
            "install malware",
            "steal credentials",
        ],
    }

    detected_threats = []
    matched_indicators = []

    for category, signatures in threat_signatures.items():

        matches = [
            signature
            for signature in signatures
            if signature in text
        ]

        if matches:

            detected_threats.append(category)

            matched_indicators.extend(matches)

    # ========================================================
    # BASE RISK
    # ========================================================

    risk_score = 10

    # ========================================================
    # ATTACK TYPE SCORE
    # ========================================================

    attack_type_scores = {

        "Prompt Injection": 25,
        "Jailbreak": 35,
        "Sensitive Information": 30,
        "Malicious Instruction": 35,
        "System Prompt Extraction": 30,
        "Role Manipulation": 20,
        "Data Exfiltration": 35,
    }

    risk_score += attack_type_scores.get(
        attack_type,
        15
    )

    # ========================================================
    # THREAT SCORE
    # ========================================================

    threat_scores = {

        "Prompt Injection": 15,
        "System Prompt Extraction": 20,
        "Jailbreak": 30,
        "Role Manipulation": 15,
        "Sensitive Information": 25,
        "Data Exfiltration": 30,
        "Malicious Instruction": 30,
    }

    for threat in detected_threats:

        risk_score += threat_scores.get(
            threat,
            10
        )

    # Multiple threat bonus

    if len(detected_threats) >= 2:
        risk_score += 10

    if len(detected_threats) >= 3:
        risk_score += 10

    # Indicator bonus

    if len(matched_indicators) >= 2:
        risk_score += 5

    if len(matched_indicators) >= 4:
        risk_score += 5

    # Limit

    risk_score = min(
        risk_score,
        100
    )

    # ========================================================
    # INITIAL DECISION
    # ========================================================

    if risk_score >= 70:

        decision = "BLOCK"
        risk_level = "HIGH"

    elif risk_score >= 40:

        decision = "REVIEW"
        risk_level = "MEDIUM"

    else:

        decision = "ALLOW"
        risk_level = "LOW"

    # ========================================================
    # PRIMARY THREAT
    # ========================================================

    if detected_threats:

        primary_threat = detected_threats[0]

    else:

        primary_threat = "No Threat Detected"

    return {

        "risk_score": risk_score,

        "risk_level": risk_level,

        "decision": decision,

        "matched_indicators": matched_indicators,

        "detected_threats": detected_threats,

        "primary_threat": primary_threat,

        "threat_count": len(
            detected_threats
        )
    }


# ============================================================
# POLICY GATEWAY
# ============================================================

def evaluate_policy(analysis):

    risk_score = analysis["risk_score"]

    decision = analysis["decision"]

    threat_count = analysis["threat_count"]

    primary_threat = analysis["primary_threat"]

    # ========================================================
    # HIGH RISK POLICY
    # ========================================================

    if risk_score >= 70:

        return {

            "policy_id": "AI-SAFETY-001",

            "policy_name": "High Risk AI Attack Prevention",

            "decision": "BLOCK",

            "action_taken": "INTERCEPTED",

            "intercepted": True,

            "reason": (
                "High-risk adversarial behavior detected. "
                f"Primary threat: {primary_threat}."
            )
        }

    # ========================================================
    # MEDIUM RISK POLICY
    # ========================================================

    if risk_score >= 40:

        return {

            "policy_id": "AI-SAFETY-002",

            "policy_name": "Medium Risk Security Review",

            "decision": "REVIEW",

            "action_taken": "FLAGGED_FOR_REVIEW",

            "intercepted": True,

            "reason": (
                "Potentially unsafe behavior detected. "
                f"{threat_count} threat category(s) require review."
            )
        }

    # ========================================================
    # LOW RISK POLICY
    # ========================================================

    return {

        "policy_id": "AI-SAFETY-003",

        "policy_name": "Low Risk Request Allowance",

        "decision": "ALLOW",

        "action_taken": "FORWARDED_TO_MODEL",

        "intercepted": False,

        "reason": (
            "No significant adversarial indicators "
            "were detected. Request may proceed."
        )
    }


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():

    return {

        "service": "Bayora Security API",

        "status": "operational",

        "version": "2.0.0",

        "components": {

            "security_engine": "active",

            "policy_gateway": "active",

            "audit_logging": "active",

            "database": "sqlite"
        }
    }


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
def health():

    return {

        "status": "healthy",

        "service": "bayora-security-engine",

        "policy_gateway": "active"
    }


# ============================================================
# API STATUS
# ============================================================

@app.get("/api/status")
def api_status():

    conn = get_db()

    total_tests = conn.execute(
        "SELECT COUNT(*) FROM audit_logs"
    ).fetchone()[0]

    blocked = conn.execute(
        "SELECT COUNT(*) FROM audit_logs WHERE decision = 'BLOCK'"
    ).fetchone()[0]

    review = conn.execute(
        "SELECT COUNT(*) FROM audit_logs WHERE decision = 'REVIEW'"
    ).fetchone()[0]

    allowed = conn.execute(
        "SELECT COUNT(*) FROM audit_logs WHERE decision = 'ALLOW'"
    ).fetchone()[0]

    conn.close()

    return {

        "bayora": "online",

        "security_engine": "active",

        "threat_detection": "active",

        "policy_gateway": "active",

        "audit_logging": "active",

        "database": "sqlite",

        "total_tests": total_tests,

        "blocked_attacks": blocked,

        "reviewed_attacks": review,

        "allowed_requests": allowed,

        "api_version": "2.0.0"
    }


# ============================================================
# SECURITY TEST
# ============================================================

@app.post("/api/security-test")
def security_test(data: dict):

    # ========================================================
    # INPUT
    # ========================================================

    prompt = str(
        data.get(
            "prompt",
            ""
        )
    ).strip()

    attack_type = str(
        data.get(
            "attack_type",
            "Prompt Injection"
        )
    )

    # ========================================================
    # VALIDATION
    # ========================================================

    if not prompt:

        return {

            "success": False,

            "error": "Security test prompt cannot be empty."
        }

    # ========================================================
    # SECURITY ENGINE
    # ========================================================

    analysis = analyze_security(
        prompt,
        attack_type
    )

    # ========================================================
    # POLICY GATEWAY
    # ========================================================

    policy = evaluate_policy(
        analysis
    )

    # ========================================================
    # INCIDENT ID
    # ========================================================

    incident_id = (

        "BY-"

        + str(
            uuid.uuid4()
        ).replace(
            "-",
            ""
        )[:8].upper()
    )

    # ========================================================
    # TIMESTAMP
    # ========================================================

    timestamp = datetime.now().isoformat()

    # ========================================================
    # DATABASE
    # ========================================================

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

            matched_indicators,

            detected_threats,

            primary_threat,

            threat_count,

            policy_id,

            policy_reason,

            action_taken,

            intercepted

        )

        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,

        (

            incident_id,

            timestamp,

            attack_type,

            prompt,

            analysis["risk_score"],

            analysis["risk_level"],

            policy["decision"],

            json.dumps(
                analysis["matched_indicators"]
            ),

            json.dumps(
                analysis["detected_threats"]
            ),

            analysis["primary_threat"],

            analysis["threat_count"],

            policy["policy_id"],

            policy["reason"],

            policy["action_taken"],

            1 if policy["intercepted"] else 0
        )
    )

    conn.commit()

    conn.close()

    # ========================================================
    # RESPONSE MESSAGE
    # ========================================================

    if policy["decision"] == "BLOCK":

        message = (
            "Request intercepted and blocked "
            "by the Bayora Policy Gateway."
        )

    elif policy["decision"] == "REVIEW":

        message = (
            "Request intercepted and flagged "
            "for security review."
        )

    else:

        message = (
            "Request passed policy evaluation "
            "and may proceed to the model."
        )

    # ========================================================
    # FINAL RESPONSE
    # ========================================================

    return {

        "success": True,

        "incident_id": incident_id,

        "timestamp": timestamp,

        "attack_type": attack_type,

        # Security analysis

        "risk_score": analysis[
            "risk_score"
        ],

        "risk_level": analysis[
            "risk_level"
        ],

        "decision": policy[
            "decision"
        ],

        "matched_indicators": analysis[
            "matched_indicators"
        ],

        "detected_threats": analysis[
            "detected_threats"
        ],

        "primary_threat": analysis[
            "primary_threat"
        ],

        "threat_count": analysis[
            "threat_count"
        ],

        # Policy Gateway

        "policy_id": policy[
            "policy_id"
        ],

        "policy_name": policy[
            "policy_name"
        ],

        "policy_reason": policy[
            "reason"
        ],

        "action_taken": policy[
            "action_taken"
        ],

        "intercepted": policy[
            "intercepted"
        ],

        "message": message
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

            matched_indicators,

            detected_threats,

            primary_threat,

            threat_count,

            policy_id,

            policy_reason,

            action_taken,

            intercepted

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

            "incident_id":
                row["incident_id"],

            "timestamp":
                row["timestamp"],

            "attack_type":
                row["attack_type"],

            "prompt":
                row["prompt"],

            "risk_score":
                row["risk_score"],

            "risk_level":
                row["risk_level"],

            "decision":
                row["decision"],

            "matched_indicators":
                json.loads(
                    row["matched_indicators"]
                ),

            "detected_threats":
                json.loads(
                    row["detected_threats"]
                ),

            "primary_threat":
                row["primary_threat"],

            "threat_count":
                row["threat_count"],

            "policy_id":
                row["policy_id"],

            "policy_reason":
                row["policy_reason"],

            "action_taken":
                row["action_taken"],

            "intercepted":
                bool(
                    row["intercepted"]
                )
        })

    return {

        "success": True,

        "count": len(logs),

        "logs": logs
    }


# ============================================================
# CLEAR AUDIT LOGS
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

    print("          BAYORA SECURITY ENGINE")

    print("==========================================")

    print("Security Engine : ACTIVE")

    print("Threat Detection: ACTIVE")

    print("Policy Gateway  : ACTIVE")

    print("Audit Logging   : ACTIVE")

    print("Database        : SQLite")

    print("Policy System   : ACTIVE")

    print("API Version     : 2.0.0")

    print("==========================================")

    print("")