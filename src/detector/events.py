from dataclasses import dataclass
from datetime import datetime

@dataclass(frozen=True)
class WirelessEvent:
    timestamp: datetime
    frame_type: str
    source: str
    destination: str
    reason_code: int | None = None

    @property
    def is_deauth(self) -> bool:
        return self.frame_type.lower() == "deauthentication"

    @property
    def is_disassoc(self) -> bool:
        return self.frame_type.lower() == "disassociation"

    @property
    def is_broadcast(self) -> bool:
        return self.destination.lower() in {
            "ff:ff:ff:ff:ff:ff",
            "ff-ff-ff-ff-ff-ff",
        }
