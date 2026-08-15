import customtkinter as ctk

def create_header(parent):
    frame = ctk.CTkFrame(parent, fg_color="transparent")
    frame.pack(fill="x", padx=30, pady=(24, 8))

    ctk.CTkLabel(
        frame,
        text="📡 WiFi Deauthentication Attack Detector",
        font=("Segoe UI", 27, "bold"),
    ).pack(anchor="w")

    ctk.CTkLabel(
        frame,
        text="Passive 802.11 management-frame analysis with explainable behavioral detection.",
        text_color="#9aa4b2",
        font=("Segoe UI", 13),
    ).pack(anchor="w", pady=(5, 0))

    return frame
