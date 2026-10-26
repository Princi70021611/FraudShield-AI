

import re

def detect_message(message):
    text = message.lower()
    score = 0
    reasons = []

    checks = [
        (
            r"\b(share|send|tell|reveal)\b.{0,25}\b(otp|pin|password)\b",
            3,
            "Message asks you to share confidential credentials"
        ),
        (
            r"\b(account blocked|account suspended|urgent|act now|verify immediately)\b",
            2,
            "Urgent or threatening language"
        ),
        (
            r"\b(prize|lottery|winner|free reward|cashback)\b",
            1,
            "Unexpected reward or prize claim"
        ),
        (
            r"\b(upi pin|cvv|bank password)\b",
            2,
            "Sensitive banking information mentioned"
        ),
        (
            r"https?://\S+|www\.\S+",
            1,
            "Message contains a link; verify it before opening"
        )
    ]

    for pattern, points, reason in checks:
        if re.search(pattern, text):
            score += points
            reasons.append(reason)

    if score >= 4:
        risk = "High"
    elif score >= 2:
        risk = "Medium"
    else:
        risk = "Low"

    if not reasons:
        reasons.append("No obvious warning signs detected")

    return {
        "risk": risk,
        "score": score,
        "reasons": reasons
    }
