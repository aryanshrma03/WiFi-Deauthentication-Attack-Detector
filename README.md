# 📡 WiFi Deauthentication Attack Detector

A defensive Wi-Fi security tool that detects **potential IEEE 802.11 deauthentication/disassociation attacks** by analyzing wireless management frames.

The project supports two safe workflows:

- **Offline PCAP analysis** — recommended for testing and demonstrations.
- **Live packet monitoring** — available when the operating system and wireless adapter provide suitable capture access.

> **Defensive use only:** this project detects suspicious wireless management traffic. It does not transmit deauthentication frames, disconnect clients, or perform attacks.

---

## 🎯 What It Detects

The detector looks for behavioral indicators such as:

- High-rate deauthentication frames
- High-rate disassociation frames
- A single transmitter targeting many stations
- Broadcast deauthentication bursts
- Repeated activity against one client
- Short-window management-frame bursts

It produces:

```text
Risk Score: 0–100
Severity: NORMAL / LOW / MEDIUM / HIGH / CRITICAL
Reasons: Explainable detection signals
```

This is a heuristic detector, not proof that an attack is occurring.

---

## 🧠 Detection Pipeline

```text
802.11 Capture / PCAP
        │
        ▼
Packet Parser
        │
        ▼
Management Frame Filter
        │
        ├── Deauthentication
        ├── Disassociation
        └── Source / Destination MACs
                │
                ▼
        Sliding-Window Analysis
                │
                ▼
       Behavioral Risk Engine
                │
                ▼
       Score + Severity + Alerts
```

---

## 🚀 Features

- 📡 802.11 deauthentication detection
- 🔌 Disassociation detection
- ⚡ Burst-rate analysis
- 🎯 Source/target relationship analysis
- 📢 Broadcast-target detection
- 📈 0–100 risk score
- 🚦 Normal / Low / Medium / High / Critical
- 🚨 Explainable alerts
- 📂 Offline `.pcap` / `.pcapng` analysis
- 🖥️ CustomTkinter dashboard
- 🧪 Built-in synthetic event simulation
- 🧩 Modular architecture
- 🧪 Unit tests
- 📝 GitHub-ready documentation

---

## ⚠️ Important Limitations

A high deauthentication rate does **not automatically mean an attack**.

Legitimate causes can include:

- Access-point roaming behavior
- Client reconnects
- Network troubleshooting
- Wireless interference
- AP restarts
- Driver issues
- Enterprise WLAN management

For production detection, combine frame-level indicators with:

- AP identity
- BSSID/channel information
- RSSI
- Protected Management Frames (802.11w / PMF)
- Client roaming telemetry
- Access-point logs
- Wireless IDS/IPS telemetry

---

## 🔒 Safety

This project is **passive/defensive**.

It does not contain code for:

- Sending deauthentication packets
- Disconnecting wireless clients
- Creating rogue APs
- Jamming radio frequencies
- Credential capture
- Wi-Fi exploitation

The built-in simulator generates synthetic events in memory for development and UI testing.

---

## 📂 Project Structure

```text
WiFi-Deauthentication-Attack-Detector/
│
├── src/
│   ├── main.py
│   │
│   ├── app/
│   │   ├── __init__.py
│   │   └── gui.py
│   │
│   ├── detector/
│   │   ├── __init__.py
│   │   ├── events.py
│   │   └── engine.py
│   │
│   ├── capture/
│   │   ├── __init__.py
│   │   ├── pcap_reader.py
│   │   └── live_monitor.py
│   │
│   ├── components/
│   │   ├── __init__.py
│   │   ├── header.py
│   │   ├── controls.py
│   │   ├── risk_meter.py
│   │   └── event_log.py
│   │
│   └── config/
│       ├── __init__.py
│       └── theme.py
│
├── tests/
│   ├── __init__.py
│   └── test_detector.py
│
├── .gitignore
├── requirements.txt
└── README.md
```

---

## 📦 Installation

```bash
git clone https://github.com/aryanshrma03/WiFi-Deauthentication-Attack-Detector.git
cd WiFi-Deauthentication-Attack-Detector

python -m venv .venv
```

Windows:

```bash
.venv\Scripts\activate
```

Linux/macOS:

```bash
source .venv/bin/activate
```

Install:

```bash
pip install -r requirements.txt
```

---

## ▶️ Run the Dashboard

```bash
python src/main.py
```

The dashboard provides:

- PCAP file selection
- Offline analysis
- Synthetic attack simulation
- Risk score
- Alert reasons
- Event statistics

---

## 📂 Analyze a PCAP

Use **Analyze PCAP** in the GUI and select a capture containing 802.11 management frames.

Supported extensions:

```text
.pcap
.pcapng
```

The application extracts only relevant management-frame metadata and feeds it to the detector.

---

## 🧪 Synthetic Simulation

The GUI includes:

### Normal Traffic

Generates a small amount of deauthentication/disassociation activity spread across time.

### Suspicious Burst

Generates a concentrated burst from one transmitter toward multiple targets.

No radio packets are transmitted.

---

## 🧮 Risk Scoring

The default heuristic engine considers:

| Indicator | Effect |
|---|---|
| Low event rate | Little/no risk |
| Moderate burst | Increased risk |
| High burst | High risk |
| Broadcast deauth burst | Strong signal |
| One source → many targets | Strong signal |
| Repeated same-target activity | Moderate signal |

Severity:

```text
0–19     NORMAL
20–39    LOW
40–59    MEDIUM
60–79    HIGH
80–100   CRITICAL
```

The thresholds are intentionally configurable in the detector code.

---

## 🧪 Tests

Run:

```bash
python -m unittest discover -s tests -v
```

The tests cover:

- Empty detector state
- Normal traffic
- High-rate events
- Broadcast bursts
- One-source/many-target behavior
- Score capping

---

## 🛠️ Live Monitoring

Live monitoring depends heavily on the OS, adapter, driver, and capture permissions.

The included module provides a **passive Scapy-based capture path**.

On supported Linux systems, monitor mode/capture permissions may be required.

Example concept:

```python
from capture.live_monitor import monitor_interface

monitor_interface("wlan0", callback)
```

The callback receives only parsed deauthentication/disassociation metadata.

No packets are transmitted.

---

## 🔮 Future Improvements

- [ ] Windows Npcap integration
- [ ] Channel hopping support
- [ ] RSSI-aware scoring
- [ ] BSSID/AP correlation
- [ ] PMF-aware detection
- [ ] SQLite alert history
- [ ] JSON/CSV export
- [ ] Email/webhook alerts
- [ ] Real-time charts
- [ ] Machine-learning anomaly detection
- [ ] Wi-Fi IDS rules
- [ ] Multi-interface monitoring
- [ ] Enterprise AP log correlation

---

## 👨‍💻 Author

**Aryan Sharma**

Cybersecurity-focused Python project demonstrating defensive wireless monitoring and explainable Wi-Fi deauthentication attack detection.
