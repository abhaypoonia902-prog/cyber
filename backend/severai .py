KNOWLEDGE = {
    "sql injection": {
        "explanation": "SQL injection happens when user input is concatenated into SQL queries.",
        "risk": "Attackers can read, modify, or delete database records.",
        "prevention": "Use parameterized queries, ORM bindings, and strict input validation.",
    },
    "brute force": {
        "explanation": "Brute-force attacks repeatedly guess credentials to gain access.",
        "risk": "Successful login can lead to account takeover.",
        "prevention": "Enable rate limiting, MFA, and IP blocking after failed attempts.",
    },
    "port scan": {
        "explanation": "Port scanning probes open services on a host.",
        "risk": "It is often the first step before exploitation.",
        "prevention": "Close unused ports and monitor reconnaissance patterns.",
    },
    "xss": {
        "explanation": "Cross-site scripting injects malicious scripts into web pages.",
        "risk": "Attackers can steal sessions or deface applications.",
        "prevention": "Encode output, use CSP, and sanitize all user input.",
    },
}

class AIService:
    def answer(self, question: str, analysis_data: dict | None = None) -> dict:
        q = question.lower().strip()
        for key, val in KNOWLEDGE.items():
            if key in q:
                return val

        if analysis_data:
            score = analysis_data.get("risk_score", 0)
            return {
                "explanation": f"Your latest analysis shows a risk score of {score}/100.",
                "risk": "High" if score >= 60 else "Moderate" if score >= 40 else "Low",
                "prevention": "Block suspicious IPs, review critical events, and preserve logs for forensics.",
            }

        return {
            "explanation": "I can explain cybersecurity concepts and LogSentinel analysis results.",
            "risk": "Depends on the threat type and exposure.",
            "prevention": "Apply defense in depth: monitoring, patching, least privilege, and secure coding.",
        }
