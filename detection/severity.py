"""Map model outputs to display severity and trigger policy."""

from __future__ import annotations


def map_scores_to_alert(
    confidence_01: float, label: str, if_prob: float, disagree: bool
) -> tuple[str, bool]:
    """
    Return (severity, should_alert). confidence_01 in [0,1]
    """
    if label == "Benign" and if_prob < 0.6 and not disagree:
        return "info", False
    if label == "Benign" and if_prob >= 0.6:
        return "high", True
    if label in ("DoS", "DDoS") and confidence_01 > 0.6:
        return "critical", True
    if label in ("PortScan",) and confidence_01 > 0.55:
        return "high", True
    if label in ("BruteForce",) and confidence_01 > 0.5:
        return "high", True
    if disagree:
        return "medium", True
    if confidence_01 > 0.75:
        return "critical", True
    if confidence_01 > 0.55:
        return "high", True
    if confidence_01 > 0.45:
        return "medium", True
    return "low", True
