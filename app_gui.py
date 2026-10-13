"""
NetPacket-Sentinel-AI - Tactical Cyber SOC Deck Entry Point Wrapper
Launches the GUI from the ui package.
"""
import sys
import os

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ui.app_gui import launch_gui

if __name__ == "__main__":
    pcap_arg = sys.argv[1] if len(sys.argv) > 1 else None
    launch_gui(pcap_arg)
