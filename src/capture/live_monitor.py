from scapy.all import Dot11, Dot11Deauth, Dot11Disas, sniff

from detector.events import WirelessEvent

def monitor_interface(interface: str, callback):
    """Passively monitor 802.11 management frames.

    The function only observes packets and invokes callback(event).
    It does not transmit packets.
    """
    from datetime import datetime, timezone

    def handle(packet):
        if not packet.haslayer(Dot11):
            return

        dot11 = packet[Dot11]

        if packet.haslayer(Dot11Deauth):
            frame_type = "deauthentication"
            reason = int(packet[Dot11Deauth].reason)
        elif packet.haslayer(Dot11Disas):
            frame_type = "disassociation"
            reason = int(packet[Dot11Disas].reason)
        else:
            return

        event = WirelessEvent(
            timestamp=datetime.now(timezone.utc),
            frame_type=frame_type,
            source=(dot11.addr2 or "unknown").lower(),
            destination=(dot11.addr1 or "unknown").lower(),
            reason_code=reason,
        )

        callback(event)

    sniff(
        iface=interface,
        prn=handle,
        store=False,
        filter="type mgt",
    )
