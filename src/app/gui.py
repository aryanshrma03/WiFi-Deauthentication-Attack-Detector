import customtkinter as ctk
from tkinter import filedialog, messagebox

from capture.pcap_reader import read_pcap
from components.controls import create_controls
from components.event_log import EventLog
from components.header import create_header
from components.risk_meter import RiskMeter
from config.theme import load_theme
from detector.engine import DeauthDetector
from detector.events import WirelessEvent

load_theme()

class WiFiDetectorApp:
    def __init__(self):
        self.root = ctk.CTk()
        self.root.title("WiFi Deauthentication Attack Detector")
        self.root.geometry("980x760")
        self.root.minsize(850, 680)

        self.detector = DeauthDetector()

        create_header(self.root)

        self.path_var = ctk.StringVar()

        self.path_entry = ctk.CTkEntry(
            self.root,
            textvariable=self.path_var,
            placeholder_text="Select a .pcap or .pcapng capture...",
            height=42,
            font=("Segoe UI", 12),
            corner_radius=10,
        )
        self.path_entry.pack(fill="x", padx=30, pady=(4, 5))

        create_controls(
            self.root,
            self.browse,
            self.analyze,
            self.simulate,
            self.reset,
        )

        self.risk = RiskMeter(self.root)
        self.log = EventLog(self.root)

        self.stats = ctk.CTkLabel(
            self.root,
            text="Events: 0 | Deauth: 0 | Disassoc: 0 | Broadcast: 0 | Sources: 0 | Targets: 0",
            text_color="#9aa4b2",
            font=("Segoe UI", 11),
        )
        self.stats.pack(anchor="w", padx=30, pady=(2, 4))

        ctk.CTkLabel(
            self.root,
            text="⚠ Passive detector only. It does not transmit deauthentication frames or disconnect clients.",
            text_color="#9aa4b2",
            font=("Segoe UI", 11),
        ).pack(anchor="w", padx=30, pady=(0, 18))

        self.reset()

    def browse(self):
        path = filedialog.askopenfilename(
            title="Select Wi-Fi Capture",
            filetypes=[
                ("Packet Captures", "*.pcap *.pcapng"),
                ("All Files", "*.*"),
            ],
        )
        if path:
            self.path_var.set(path)

    def analyze(self):
        path = self.path_var.get().strip()

        if not path:
            messagebox.showwarning("Capture Required", "Select a PCAP/PCAPNG file first.")
            return

        try:
            events = list(read_pcap(path))
        except (FileNotFoundError, ValueError) as exc:
            messagebox.showerror("Capture Error", str(exc))
            return
        except Exception as exc:
            messagebox.showerror("Analysis Error", str(exc))
            return

        self.detector.reset()
        self.log.clear()

        if not events:
            self.log.add("[INFO] No deauthentication/disassociation frames found.")
            self._update(self.detector.evaluate())
            return

        result = self.detector.evaluate()

        for event in events:
            result = self.detector.add_event(event)
            self.log.add(
                f"[{event.frame_type.upper():16}] "
                f"{event.source} → {event.destination} "
                f"reason={event.reason_code}"
            )

        self._update(result)
        self._log_reasons(result)

    def simulate(self):
        from datetime import datetime, timedelta

        self.detector.reset()
        self.log.clear()

        now = datetime.now()

        # Synthetic in-memory traffic only. No radio activity is generated.
        for i in range(24):
            event = WirelessEvent(
                timestamp=now + timedelta(milliseconds=i * 150),
                frame_type="deauthentication",
                source="02:00:00:aa:bb:cc",
                destination=(
                    "ff:ff:ff:ff:ff:ff"
                    if i < 8
                    else f"02:00:00:00:00:{i:02x}"
                ),
                reason_code=7,
            )
            result = self.detector.add_event(event)
            self.log.add(
                f"[SIMULATED DEAUTH] {event.source} → {event.destination} "
                f"reason={event.reason_code}"
            )

        self._update(result)
        self._log_reasons(result)

    def reset(self):
        self.detector.reset()
        self.log.clear()
        self.path_var.set("")

        result = self.detector.evaluate()
        self._update(result)

        self.log.add("[INFO] Detector reset. Ready for passive analysis.")
        self.log.add("[INFO] Synthetic simulation does not transmit packets.")

    def _update(self, result):
        self.risk.update(result)
        self.stats.configure(
            text=(
                f"Events: {result.event_count} | "
                f"Deauth: {result.deauth_count} | "
                f"Disassoc: {result.disassoc_count} | "
                f"Broadcast: {result.broadcast_count} | "
                f"Sources: {result.unique_sources} | "
                f"Targets: {result.unique_targets}"
            )
        )

    def _log_reasons(self, result):
        if result.reasons:
            self.log.add("")
            self.log.add(f"[ALERT] Severity: {result.severity}")
            for reason in result.reasons:
                self.log.add(f"  • {reason}")
        else:
            self.log.add("[INFO] No strong attack pattern detected.")

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    WiFiDetectorApp().run()
