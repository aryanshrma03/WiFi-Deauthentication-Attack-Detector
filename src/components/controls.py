import customtkinter as ctk

def create_controls(parent, browse_command, analyze_command, simulate_command, reset_command):
    frame = ctk.CTkFrame(parent, fg_color="transparent")
    frame.pack(fill="x", padx=30, pady=(8, 8))

    ctk.CTkButton(
        frame, text="Open PCAP", command=browse_command,
        width=120, height=42, corner_radius=10
    ).pack(side="left")

    ctk.CTkButton(
        frame, text="Analyze PCAP", command=analyze_command,
        width=135, height=42, corner_radius=10
    ).pack(side="left", padx=8)

    ctk.CTkButton(
        frame, text="Simulate Burst", command=simulate_command,
        width=145, height=42, corner_radius=10
    ).pack(side="left")

    ctk.CTkButton(
        frame, text="Reset", command=reset_command,
        width=100, height=42, corner_radius=10,
        fg_color="#3b3f46", hover_color="#4b5058"
    ).pack(side="right")

    return frame
