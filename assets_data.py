"""
NetPacket Inspector Pro - Assets & Branding Data Provider
Provides access to the high-resolution and optimized Kali x Wireshark emblem assets.
"""

import os

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ASSETS_DIR = os.path.join(CURRENT_DIR, "assets")

EMBLEM_IMAGE_PATH = os.path.join(ASSETS_DIR, "kali_wireshark_emblem.jpg")
EMBLEM_OPTIMIZED_PATH = os.path.join(ASSETS_DIR, "emblem_360.jpg")
EMBLEM_B64_FILE = os.path.join(ASSETS_DIR, "emblem_b64.txt")

try:
    if os.path.exists(EMBLEM_B64_FILE):
        with open(EMBLEM_B64_FILE, "r", encoding="utf-8") as f:
            EMBLEM_B64 = f.read().strip()
    else:
        EMBLEM_B64 = ""
except Exception:
    EMBLEM_B64 = ""
