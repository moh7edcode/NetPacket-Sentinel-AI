"""
NetPacket Inspector - Network File Carving & Artifact Extraction Engine
Reconstructs transmitted files (HTTP transfers, payloads, scripts, images, PDFs, EXEs) from packet streams.
"""

import os
import re
import hashlib
from typing import List, Dict, Any
from core.pcap_parser import ParsedPacket


class CarvedFile:
    """Represents an extracted file artifact from network traffic."""

    def __init__(
        self,
        file_id: int,
        filename: str,
        file_type: str,
        source_ip: str,
        dest_ip: str,
        protocol: str,
        packet_nums: List[int],
        content: bytes
    ):
        self.file_id = file_id
        self.filename = filename
        self.file_type = file_type
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.protocol = protocol
        self.packet_nums = packet_nums
        self.content = content
        self.size_bytes = len(content)
        self.md5 = hashlib.md5(content).hexdigest()
        self.sha256 = hashlib.sha256(content).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "File_ID": self.file_id,
            "Filename": self.filename,
            "File_Type": self.file_type,
            "Size_Bytes": self.size_bytes,
            "Size_Formatted": f"{self.size_bytes / 1024:.2f} KB" if self.size_bytes >= 1024 else f"{self.size_bytes} B",
            "Source_IP": self.source_ip,
            "Dest_IP": self.dest_ip,
            "Protocol": self.protocol,
            "MD5": self.md5,
            "SHA256": self.sha256,
            "Packet_Numbers": self.packet_nums
        }


class FileCarverEngine:
    """Carves and reconstructs transmitted files from packet captures."""

    # Common File Signatures (Magic Bytes)
    MAGIC_SIGNATURES = [
        (b"MZ", "Executable (.exe / .dll)", ".exe"),
        (b"%PDF", "PDF Document (.pdf)", ".pdf"),
        (b"\x89PNG\r\n\x1a\n", "PNG Image (.png)", ".png"),
        (b"\xff\xd8\xff", "JPEG Image (.jpg)", ".jpg"),
        (b"GIF89a", "GIF Image (.gif)", ".gif"),
        (b"GIF87a", "GIF Image (.gif)", ".gif"),
        (b"PK\x03\x04", "ZIP / Office Document (.zip/.docx)", ".zip"),
        (b"\x1f\x8b", "GZIP Compressed Archive (.gz)", ".gz"),
        (b"<!DOCTYPE html", "HTML Web Document (.html)", ".html"),
        (b"<html", "HTML Web Document (.html)", ".html"),
        (b"<?xml", "XML Data Document (.xml)", ".xml"),
        (b"powershell", "PowerShell Script (.ps1)", ".ps1"),
        (b"#!/bin/", "Shell Script (.sh)", ".sh")
    ]

    @classmethod
    def carve_files_from_packets(cls, packets: List[ParsedPacket]) -> List[CarvedFile]:
        """Scans packet payloads and HTTP transactions to isolate files."""
        carved_files: List[CarvedFile] = []
        file_counter = 1

        # 1. HTTP Body Extraction
        for p in packets:
            if p.protocol == "HTTP" and len(p.raw_data) > 54:
                raw_text = p.raw_data.decode("latin-1", errors="ignore")
                if "\r\n\r\n" in raw_text:
                    hdr_part, body_part = raw_text.split("\r\n\r\n", 1)
                    body_bytes = p.raw_data[p.raw_data.find(b"\r\n\r\n") + 4:]

                    if len(body_bytes) >= 16:
                        # Determine file type
                        ftype, ext = cls._detect_file_type(body_bytes, hdr_part)
                        # Extract URI or filename
                        fname = cls._extract_filename(hdr_part, ext, file_counter)

                        carved_files.append(CarvedFile(
                            file_id=file_counter,
                            filename=fname,
                            file_type=ftype,
                            source_ip=p.src,
                            dest_ip=p.dst,
                            protocol="HTTP",
                            packet_nums=[p.packet_num],
                            content=body_bytes
                        ))
                        file_counter += 1

        # 2. Raw Stream Carving for Script Injections & Backdoor Payloads (e.g. C2 scripts)
        for p in packets:
            if p.protocol in ("TCP", "Raw Data") and len(p.raw_data) > 54:
                payload = p.raw_data[54:]
                if b"powershell" in payload.lower() or b"downloadstring" in payload.lower() or b"cmd.exe" in payload.lower():
                    # Avoid duplicate if already carved
                    if not any(p.packet_num in cf.packet_nums for cf in carved_files):
                        carved_files.append(CarvedFile(
                            file_id=file_counter,
                            filename=f"c2_script_payload_{file_counter}.ps1",
                            file_type="PowerShell Script / C2 Payload",
                            source_ip=p.src,
                            dest_ip=p.dst,
                            protocol=p.protocol,
                            packet_nums=[p.packet_num],
                            content=payload
                        ))
                        file_counter += 1

        return carved_files

    @classmethod
    def _detect_file_type(cls, data: bytes, header_text: str = "") -> tuple:
        """Detect file type and recommended extension from magic bytes or Content-Type header."""
        for magic, desc, ext in cls.MAGIC_SIGNATURES:
            if data.startswith(magic) or magic in data[:64]:
                return desc, ext

        if "Content-Type: text/html" in header_text:
            return "HTML Web Page (.html)", ".html"
        if "Content-Type: application/json" in header_text:
            return "JSON Data Payload (.json)", ".json"
        if "Content-Type: application/javascript" in header_text:
            return "JavaScript Source (.js)", ".js"

        return "Generic Binary Payload (.bin)", ".bin"

    @classmethod
    def _extract_filename(cls, header_text: str, default_ext: str, count: int) -> str:
        """Extract filename from HTTP URI or Content-Disposition."""
        cd_match = re.search(r'filename=["\']?([^"\';\r\n]+)', header_text)
        if cd_match:
            return cd_match.group(1).strip()

        # Try from GET/POST URI
        uri_match = re.search(r"(?:GET|POST)\s+([^\s?]+)", header_text)
        if uri_match:
            path = uri_match.group(1).strip("/")
            basename = os.path.basename(path)
            if basename and "." in basename:
                return basename

        return f"extracted_artifact_{count}{default_ext}"
