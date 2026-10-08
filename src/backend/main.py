from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
import uuid

app = FastAPI(
    title="Bayora Security API",
    description="AI adversarial security testing backend",
    version="1.0.0"
)

# ============================================================
# CORS CONFIGURATION
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=".*",
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# AUDIT LOGS
# ============================================================

audit_logs = []


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
    ]

    matches = [
        indicator
        for indicator in indicators
        if indicator in text
    ]

    risk_score = 15

    if attack_type == "Prompt Injection":
        risk_score += 25

    elif attack_type == "Jailbreak":
        risk_score += 35

    elif attack_type == "Sensitive Information":
        risk_score += 30

    elif attack_type == "Malicious Instruction":
        risk_score += 30

    if matches:
        risk_score += min(len(matches) * 12, 45)

    risk_score = min(risk_score, 100)

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
# ROOT
# ============================================================

@app.get("/")
def root():

    return {
        "service": "Bayora Security API",
        "status": "operational"
    }


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
def health():

    return {
        "status": "healthy",
        "service": "bayora-security-engine"
    }


# ============================================================
# SECURITY TEST
# ============================================================

@app.post("/api/security-test")
def security_test(data: dict):

    prompt = str(
        data.get("prompt", "")
    ).strip()

    attack_type = str(
        data.get(
            "attack_type",
            "Prompt Injection"
        )
    )

    if not prompt:
        return {
            "success": False,
            "error": "Security test prompt cannot be empty."
        }

    analysis = analyze_security(
        prompt,
        attack_type
    )

    incident_id = (
        "BY-"
        + str(uuid.uuid4()).replace("-", "")[:8].upper()
    )

    timestamp = datetime.now().isoformat()

    event = {
        "incident_id": incident_id,
        "timestamp": timestamp,
        "attack_type": attack_type,
        "prompt": prompt,
        **analysis,
    }

    audit_logs.insert(0, event)

    if analysis["decision"] == "BLOCK":
        message = "Request blocked by Bayora policy."

    elif analysis["decision"] == "REVIEW":
        message = "Request flagged for security review."

    else:
        message = "Request passed Bayora policy evaluation."

    return {
        "success": True,
        "incident_id": incident_id,
        "timestamp": timestamp,
        "attack_type": attack_type,
        "risk_score": analysis["risk_score"],
        "risk_level": analysis["risk_level"],
        "decision": analysis["decision"],
        "matched_indicators": analysis["matched_indicators"],
        "message": message,
    }


# ============================================================
# AUDIT LOGS
# ============================================================

@app.get("/api/audit-logs")
def get_audit_logs():

    return {
        "success": True,
        "count": len(audit_logs),
        "logs": audit_logs[:50]
    }


# ============================================================
# STATUS
# ============================================================

@app.get("/api/status")
def api_status():

    return {
        "bayora": "online",
        "security_engine": "active",
        "audit_logging": "active",
        "total_tests": len(audit_logs),
        "api_version": "1.0.0"
    }