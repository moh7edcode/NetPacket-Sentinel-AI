"""
NetPacket Inspector - Payload Decoding & De-obfuscation Engine
Automatically identifies and decodes Base64, URL encoding, Hex, Gzip/Zlib, Unicode, and calculates Shannon Entropy.
"""

import math
import base64
import urllib.parse
import zlib
import re
from typing import Dict, Any, List, Optional


class PayloadDecoder:
    """Detects, analyzes, and decodes various payload encodings and obfuscations."""

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calculates Shannon Entropy (0.0 to 8.0). High entropy (>7.2) indicates encryption/compression/tunneling."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        byte_counts = [0] * 256
        for b in data:
            byte_counts[b] += 1

        for count in byte_counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return round(entropy, 3)

    @classmethod
    def analyze_and_decode(cls, raw_data: bytes) -> Dict[str, Any]:
        """Comprehensive multi-format analysis and automatic decoding."""
        if not raw_data:
            return {
                "Entropy": 0.0,
                "Is_High_Entropy": False,
                "Decodings": [],
                "Plaintext_Preview": "(Empty Payload)"
            }

        entropy = cls.calculate_entropy(raw_data)
        is_high_entropy = entropy >= 7.2

        decodings: List[Dict[str, str]] = []

        # 1. Plaintext Extraction
        try:
            ascii_text = raw_data.decode("utf-8", errors="ignore")
            printable_ratio = sum(1 for c in ascii_text if c.isprintable() or c in "\r\n\t") / max(1, len(ascii_text))
            if printable_ratio > 0.6:
                decodings.append({
                    "Type": "Plaintext / UTF-8",
                    "Confidence": f"{int(printable_ratio * 100)}%",
                    "Result": ascii_text[:500]
                })
        except Exception:
            ascii_text = ""

        # 2. URL Percent-Decoding
        if "%" in ascii_text:
            try:
                url_decoded = urllib.parse.unquote(ascii_text)
                if url_decoded != ascii_text and len(url_decoded) > 3:
                    decodings.append({
                        "Type": "URL Percent-Decoded",
                        "Confidence": "High",
                        "Result": url_decoded[:500]
                    })
            except Exception:
                pass

        # 3. Base64 Detection & Decoding
        b64_matches = re.findall(r"(?:[A-Za-z0-9+/]{4}){3,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?", ascii_text)
        for candidate in b64_matches:
            if len(candidate) >= 12:
                try:
                    decoded_bytes = base64.b64decode(candidate, validate=True)
                    decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
                    if any(c.isalnum() for c in decoded_str):
                        decodings.append({
                            "Type": f"Base64 Decoded ('{candidate[:16]}...')",
                            "Confidence": "High",
                            "Result": decoded_str[:500]
                        })
                except Exception:
                    pass

        # 4. Gzip / Zlib Decompression
        if len(raw_data) >= 10 and raw_data[:2] == b"\x1f\x8b":  # Gzip magic
            try:
                decompressed = zlib.decompress(raw_data, 16 + zlib.MAX_WBITS)
                decodings.append({
                    "Type": "Gzip Decompressed",
                    "Confidence": "Very High",
                    "Result": decompressed.decode("utf-8", errors="replace")[:500]
                })
            except Exception:
                pass
        elif len(raw_data) >= 6 and raw_data[:2] in (b"\x78\x9c", b"\x78\x01", b"\x78\xda"):  # Zlib magic
            try:
                decompressed = zlib.decompress(raw_data)
                decodings.append({
                    "Type": "Zlib Decompressed",
                    "Confidence": "Very High",
                    "Result": decompressed.decode("utf-8", errors="replace")[:500]
                })
            except Exception:
                pass

        # 5. Hex Stream Decoding (e.g. 48656c6c6f)
        hex_candidates = re.findall(r"\b[0-9a-fA-F]{8,}\b", ascii_text)
        for h in hex_candidates:
            if len(h) % 2 == 0 and len(h) >= 10:
                try:
                    hex_decoded = bytes.fromhex(h).decode("utf-8", errors="ignore")
                    if sum(1 for c in hex_decoded if c.isprintable()) / len(hex_decoded) > 0.7:
                        decodings.append({
                            "Type": f"Hex Stream Decoded ('{h[:16]}...')",
                            "Confidence": "High",
                            "Result": hex_decoded[:500]
                        })
                except Exception:
                    pass

        # 6. Single-Byte XOR Detector (Brute Force 1-255 for common strings)
        if len(raw_data) >= 8:
            common_targets = [b"http://", b"https://", b"GET ", b"POST ", b"cmd.exe", b"/bin/sh", b"powershell", b"This program"]
            for key in range(1, 256):
                xored = bytes(b ^ key for b in raw_data[:128])
                for target in common_targets:
                    if target in xored:
                        full_xored = bytes(b ^ key for b in raw_data)
                        decodings.append({
                            "Type": f"XOR Decoded (Key: 0x{key:02x})",
                            "Confidence": "High (Signature Match)",
                            "Result": full_xored.decode("utf-8", errors="replace")[:500]
                        })
                        break

        # Printable Preview
        preview = "".join(chr(b) if 32 <= b <= 126 else "." for b in raw_data[:100])

        return {
            "Entropy": entropy,
            "Is_High_Entropy": is_high_entropy,
            "Decodings": decodings,
            "Plaintext_Preview": preview
        }
