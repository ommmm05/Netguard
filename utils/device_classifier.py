"""Device classifier — re-exports port/MAC heuristics."""

from visibility.device_classifier import classify_device, oui_vendor

__all__ = ["classify_device", "oui_vendor"]
