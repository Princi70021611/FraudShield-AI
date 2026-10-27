
import re

def detect_message(message):
    text = message.lower()
    score = 0
    reasons = []

    checks = [
        (
            r"\b(share|send|tell|reveal|provide|enter)\b.{0,40}\b(otp|pin|password|cvv)\b",
            3,
            "Message asks for confidential credentials"
        ),
        (
            r"\b(account blocked|account suspended|urgent|act now|verify immediately|"
            r"immediately|within \d+ hours|will be blocked)\b",
            2,
            "Urgent or threatening language"
        ),
        (
            r"\b(prize|lottery|winner|free reward|cashback|"
            r"claim your reward|you have won)\b",
            1,
            "Unexpected reward or prize claim"
        ),
        (
            r"\b(upi pin|cvv|bank password|bank details|"
            r"otp|one time password)\b",
            2,
            "Sensitive banking information mentioned"
        ),
        (
            r"https?://\S+|www\.\S+",
            2,
            "Message contains a link; verify it carefully"
        ),
        (
            r"\b(click here|click the link|verify your account|"
            r"account will be blocked|suspended today)\b",
            1,
            "Possible phishing or account-pressure language"
        )
    ]

    for pattern, points, reason in checks:
        if re.search(pattern, text):
            score += points
            if reason not in reasons:
                reasons.append(reason)

    if score >= 5:
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
