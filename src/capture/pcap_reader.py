from pathlib import Path

from scapy.all import Dot11, Dot11Deauth, Dot11Disas, PcapReader

from detector.events import WirelessEvent

def read_pcap(path: str | Path):
    """Yield passive 802.11 deauth/disassoc metadata from a PCAP."""
    path = Path(path)

    if not path.is_file():
        raise FileNotFoundError(f"Capture not found: {path}")

    try:
        reader = PcapReader(str(path))
    except Exception as exc:
        raise ValueError(f"Could not open capture: {exc}") from exc

    try:
        for packet in reader:
            if not packet.haslayer(Dot11):
                continue

            dot11 = packet[Dot11]

            if packet.haslayer(Dot11Deauth):
                frame_type = "deauthentication"
                reason = int(packet[Dot11Deauth].reason)
            elif packet.haslayer(Dot11Disas):
                frame_type = "disassociation"
                reason = int(packet[Dot11Disas].reason)
            else:
                continue

            timestamp = packet.time
            from datetime import datetime, timezone
            dt = datetime.fromtimestamp(float(timestamp), tz=timezone.utc)

            yield WirelessEvent(
                timestamp=dt,
                frame_type=frame_type,
                source=(dot11.addr2 or "unknown").lower(),
                destination=(dot11.addr1 or "unknown").lower(),
                reason_code=reason,
            )
    finally:
        reader.close()
