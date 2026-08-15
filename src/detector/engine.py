from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import timedelta

from detector.events import WirelessEvent

@dataclass
class DetectionResult:
    score: int
    severity: str
    reasons: list[str]
    event_count: int
    deauth_count: int
    disassoc_count: int
    broadcast_count: int
    unique_sources: int
    unique_targets: int

class DeauthDetector:
    """Explainable sliding-window heuristic detector."""

    def __init__(self, window_seconds: int = 10):
        self.window_seconds = window_seconds
        self.events = deque(maxlen=5000)

    def reset(self):
        self.events.clear()

    def add_event(self, event: WirelessEvent) -> DetectionResult:
        self.events.append(event)
        return self.evaluate()

    def evaluate(self) -> DetectionResult:
        if not self.events:
            return DetectionResult(
                0, "NORMAL", [], 0, 0, 0, 0, 0, 0
            )

        now = self.events[-1].timestamp
        cutoff = now - timedelta(seconds=self.window_seconds)
        recent = [e for e in self.events if e.timestamp >= cutoff]

        deauth = [e for e in recent if e.is_deauth]
        disassoc = [e for e in recent if e.is_disassoc]
        broadcast = [e for e in deauth if e.is_broadcast]

        score = 0
        reasons = []

        if len(deauth) >= 20:
            score += 35
            reasons.append("High-rate deauthentication burst detected.")
        elif len(deauth) >= 10:
            score += 20
            reasons.append("Elevated deauthentication activity detected.")
        elif len(deauth) >= 5:
            score += 8

        if len(disassoc) >= 15:
            score += 15
            reasons.append("High-rate disassociation activity detected.")

        if len(broadcast) >= 5:
            score += 30
            reasons.append("Multiple broadcast deauthentication frames detected.")
        elif broadcast:
            score += 8
            reasons.append("Broadcast deauthentication activity observed.")

        source_targets = defaultdict(set)
        for event in deauth:
            source_targets[event.source.lower()].add(event.destination.lower())

        if any(len(targets) >= 8 for targets in source_targets.values()):
            score += 25
            reasons.append("One transmitter is targeting many stations.")

        target_counts = Counter(event.destination.lower() for event in deauth)
        if any(count >= 8 for count in target_counts.values()):
            score += 15
            reasons.append("Repeated deauthentication activity targets one station.")

        score = min(100, score)

        if score >= 80:
            severity = "CRITICAL"
        elif score >= 60:
            severity = "HIGH"
        elif score >= 40:
            severity = "MEDIUM"
        elif score >= 20:
            severity = "LOW"
        else:
            severity = "NORMAL"

        return DetectionResult(
            score=score,
            severity=severity,
            reasons=reasons,
            event_count=len(recent),
            deauth_count=len(deauth),
            disassoc_count=len(disassoc),
            broadcast_count=len(broadcast),
            unique_sources=len({e.source.lower() for e in recent}),
            unique_targets=len({e.destination.lower() for e in recent}),
        )
