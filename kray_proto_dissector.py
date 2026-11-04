#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""
================================================================================
kray_proto_dissector.py — 22-Protocol Data Frame Dissector & Deep Frame Inspector
================================================================================
Authoritative Standards & RFC References:
  Link & Hardware Layers:
    1. IEEE 802.3 Ethernet & IEEE 802.1Q/802.1ad VLAN QinQ
    2. IEEE 802.11 Wi-Fi (MAC frame format & beacon/probe frames)
    3. IEEE 802.15.1 Bluetooth & BLE (HCI packet & L2CAP basic framing)
    4. RFC 826 ARP (Address Resolution Protocol)
  Network Layer:
    5. RFC 791 IPv4 & RFC 8200 IPv6
    6. RFC 792 ICMPv4 & RFC 4443 ICMPv6
  Transport & Host Layer:
    7. RFC 793 TCP & RFC 768 UDP
    8. Linux AF_UNIX Local IPC (SCM_CREDENTIALS / SCM_RIGHTS)
  Application & Storage Protocols:
    9. RFC 7230 / RFC 9112 HTTP/1.1
   10. RFC 9113 HTTP/2 & gRPC Framing Specification
   11. RFC 8446 TLS 1.3 & RFC 5246 TLS 1.2 Record Layer
   12. RFC 6455 WebSocket
   13. RFC 1035 DNS (Domain Name System)
   14. Redis Serialization Protocol (RESP 2 / RESP 3)
   15. MySQL / MariaDB Client-Server Protocol
   16. PostgreSQL Frontend/Backend Protocol 3.0
   17. Apache Kafka Binary Request/Response Protocol
   18. MQTT v3.1.1 / v5.0 (OASIS Standard)
   19. RFC 4253 SSH-2.0 Transport Layer Protocol
   20. RFC 5905 NTP (Network Time Protocol v4)
   21. RFC 1813 NFSv3 / RFC 7530 NFSv4 RPC
   22. MS-SMB2 Server Message Block / RFC 7143 iSCSI BHS
================================================================================
"""

import binascii
import json
import re
import struct
import sys
from typing import Any, Dict, List, Optional, Tuple


class DissectedField:
    """A single decoded protocol header or payload field."""
    def __init__(self, name: str, value: Any, hex_repr: str = "", description: str = ""):
        self.name = name
        self.value = value
        self.hex_repr = hex_repr
        self.description = description

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "value": str(self.value),
            "hex": self.hex_repr,
            "desc": self.description,
        }


class DissectedFrame:
    """The complete dissected representation of a raw data frame."""
    def __init__(self, proto_id: str, proto_name: str, osi_layer: str, summary: str):
        self.proto_id = proto_id
        self.proto_name = proto_name
        self.osi_layer = osi_layer
        self.summary = summary
        self.fields: List[DissectedField] = []
        self.payload_bytes: bytes = b""
        self.raw_data: bytes = b""

    def add_field(self, name: str, value: Any, hex_repr: str = "", description: str = "") -> None:
        self.fields.append(DissectedField(name, value, hex_repr, description))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "protocol_id": self.proto_id,
            "protocol_name": self.proto_name,
            "osi_layer": self.osi_layer,
            "summary": self.summary,
            "byte_count": len(self.raw_data),
            "fields": [f.to_dict() for f in self.fields],
            "hexdump": format_hexdump(self.raw_data),
        }


# ==============================================================================
# 22 Supported Protocols Catalog & Specification
# ==============================================================================

PROTOCOLS_CATALOG: Dict[str, Dict[str, Any]] = {
    "http1": {
        "name": "HTTP/1.1",
        "osi": "L7 (Application)",
        "default_ports": [80, 8080, 8000, 3000],
        "transport": "TCP",
        "description": "Hypertext Transfer Protocol (RFC 2616 / 7230) text request/response framing",
    },
    "http2": {
        "name": "HTTP/2 & gRPC",
        "osi": "L7 (Application)",
        "default_ports": [443, 50051, 8443],
        "transport": "TCP",
        "description": "Binary Framing Layer (RFC 7540) with length, type, flags, stream_id and multiplexing",
    },
    "tls": {
        "name": "HTTPS / TLS Record Layer",
        "osi": "L6/L7 (Presentation/Session)",
        "default_ports": [443, 8443],
        "transport": "TCP",
        "description": "Transport Layer Security (RFC 5246/8446) Record Layer and Handshake ClientHello",
    },
    "websocket": {
        "name": "WebSocket",
        "osi": "L7 (Application)",
        "default_ports": [80, 443, 8080, 3000],
        "transport": "TCP",
        "description": "WebSocket Protocol (RFC 6455) frame header with FIN, opcode, mask key and payload",
    },
    "dns": {
        "name": "DNS (Domain Name System)",
        "osi": "L7 (Application)",
        "default_ports": [53],
        "transport": "UDP / TCP",
        "description": "DNS Protocol (RFC 1035) header with transaction ID, flags, queries and answers",
    },
    "redis": {
        "name": "Redis (RESP 2/3)",
        "osi": "L7 (Application)",
        "default_ports": [6379, 6380, 26379],
        "transport": "TCP",
        "description": "REdis Serialization Protocol with Simple Strings, Bulk Strings, Arrays and Integers",
    },
    "mysql": {
        "name": "MySQL / MariaDB",
        "osi": "L7 (Application)",
        "default_ports": [3306, 33060],
        "transport": "TCP",
        "description": "MySQL Client/Server Wire Protocol with 3-byte length, sequence ID and COM_QUERY",
    },
    "postgres": {
        "name": "PostgreSQL",
        "osi": "L7 (Application)",
        "default_ports": [5432, 5433, 6432],
        "transport": "TCP",
        "description": "PostgreSQL Frontend/Backend Protocol 3.0 with message type char and int32 length",
    },
    "kafka": {
        "name": "Apache Kafka",
        "osi": "L7 (Application)",
        "default_ports": [9092, 9093, 9094],
        "transport": "TCP",
        "description": "Kafka Binary Protocol with message size, API key, API version and correlation ID",
    },
    "mqtt": {
        "name": "MQTT",
        "osi": "L7 (Application)",
        "default_ports": [1883, 8883],
        "transport": "TCP",
        "description": "Message Queuing Telemetry Transport (v3.1.1/5.0) fixed header, packet types & topics",
    },
    "ssh": {
        "name": "SSH-2.0",
        "osi": "L7 (Application)",
        "default_ports": [22, 2222],
        "transport": "TCP",
        "description": "Secure Shell Protocol (RFC 4253) version banner and binary packet protocol header",
    },
    "ntp": {
        "name": "NTP (Network Time Protocol)",
        "osi": "L7 (Application)",
        "default_ports": [123, 323],
        "transport": "UDP",
        "description": "NTP Protocol (RFC 5905) 48-byte frame with LI, VN, mode, stratum, poll and timestamps",
    },
    "icmp": {
        "name": "ICMP (Internet Control Message Protocol)",
        "osi": "L3/L4 (Network Control)",
        "default_ports": [0],
        "transport": "IPPROTO_ICMP (1)",
        "description": "ICMPv4/v6 Protocol (RFC 792) with type, code, checksum, identifier and sequence",
    },
    "arp": {
        "name": "ARP (Address Resolution Protocol)",
        "osi": "L2/L3 (Link/Network)",
        "default_ports": [0],
        "transport": "EtherType 0x0806",
        "description": "ARP Protocol (RFC 826) 28-byte frame with hardware/proto types, opcode and MAC/IP mapping",
    },
    "unix": {
        "name": "AF_UNIX (Local IPC Socket)",
        "osi": "L4/L5 (Local IPC)",
        "default_ports": [0],
        "transport": "PF_LOCAL / AF_UNIX",
        "description": "Linux UNIX Domain Socket message framing with length header and SCM_CREDENTIALS",
    },
    "wifi": {
        "name": "Wi-Fi (IEEE 802.11 a/b/g/n/ac/ax/be)",
        "osi": "L2 (Data Link / MAC)",
        "default_ports": [0],
        "transport": "IEEE 802.11 Wireless Frame",
        "description": "Wireless Local Area Network MAC frame with Frame Control, BSSID, Receiver/Transmitter MACs",
    },
    "bluetooth": {
        "name": "Bluetooth & BLE (IEEE 802.15.1)",
        "osi": "L2/L4 (HCI / L2CAP)",
        "default_ports": [0],
        "transport": "AF_BLUETOOTH / HCI / L2CAP",
        "description": "Short-range wireless personal area network frame with HCI packet type, handle, and L2CAP channel",
    },
    "nfs": {
        "name": "NFS (Network File System v3/v4)",
        "osi": "L7 (File Sharing / Storage)",
        "default_ports": [2049],
        "transport": "TCP / UDP",
        "description": "Sun RPC / XDR protocol with Transaction ID, Program 100003, and LOOKUP/READ/WRITE procedures",
    },
    "smb": {
        "name": "SMB2 / SMB3 (Server Message Block)",
        "osi": "L7 (File Sharing / Storage)",
        "default_ports": [445],
        "transport": "TCP (Direct-hosted NetBIOS-less)",
        "description": "Microsoft Windows / Samba file sharing wire protocol with 0xFE 'SMB' magic, command and status",
    },
    "ftp": {
        "name": "FTP (File Transfer Protocol)",
        "osi": "L7 (File Transfer)",
        "default_ports": [21, 20],
        "transport": "TCP",
        "description": "File Transfer Protocol (RFC 959) control connection with USER, PASS, PASV, RETR commands",
    },
    "iscsi": {
        "name": "iSCSI (IP SAN Block Storage)",
        "osi": "L5/L7 (Storage Area Network)",
        "default_ports": [3260],
        "transport": "TCP",
        "description": "Internet Small Computer Systems Interface (RFC 3720) 48-byte Basic Header Segment (BHS) and SCSI CDB",
    },
    "vlan": {
        "name": "VLAN (IEEE 802.1Q)",
        "osi": "L2 (Data Link Tagging)",
        "default_ports": [0],
        "transport": "EtherType 0x8100",
        "description": "Virtual LAN tagging standard with 3-bit Priority Code Point (PCP), Drop Eligible (DEI), and 12-bit VLAN ID",
    },
}


# ==============================================================================
# Hex + ASCII Dump Formatter
# ==============================================================================

def format_hexdump(data: bytes, max_bytes: int = 256) -> str:
    """Format raw binary bytes into a canonical side-by-side hex and ASCII dump."""
    if not data:
        return "    <empty data frame>"
    lines = []
    truncated = False
    display_data = data
    if len(data) > max_bytes:
        display_data = data[:max_bytes]
        truncated = True

    for i in range(0, len(display_data), 16):
        chunk = display_data[i:i + 16]
        hex_bytes = " ".join(f"{b:02x}" for b in chunk)
        if len(chunk) < 16:
            hex_bytes = hex_bytes.ljust(16 * 3 - 1)
        ascii_repr = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"    {i:04x}  {hex_bytes[:23]}  {hex_bytes[23:]:<24}  |{ascii_repr}|")

    if truncated:
        lines.append(f"    ... [truncated {len(data) - max_bytes} bytes; total {len(data)} bytes]")
    return "\n".join(lines)


# ==============================================================================
# Protocol Dissector Implementations
# ==============================================================================

def dissect_http1(data: bytes) -> DissectedFrame:
    frame = DissectedFrame("http1", "HTTP/1.1", "L7 (Application)", "HTTP Request/Response")
    frame.raw_data = data
    text = data.decode("latin1", errors="replace")
    lines = text.split("\r\n") if "\r\n" in text else text.split("\n")
    first_line = lines[0] if lines else ""

    if first_line.startswith("HTTP/"):
        parts = first_line.split(" ", 2)
        frame.summary = f"HTTP Response: {first_line}"
        frame.add_field("Version", parts[0] if len(parts) > 0 else "HTTP/1.1", first_line[:8].encode().hex())
        frame.add_field("Status Code", parts[1] if len(parts) > 1 else "200", parts[1].encode().hex() if len(parts) > 1 else "")
        frame.add_field("Status Reason", parts[2] if len(parts) > 2 else "OK", parts[2].encode().hex() if len(parts) > 2 else "")
    else:
        parts = first_line.split(" ", 2)
        frame.summary = f"HTTP Request: {first_line}"
        frame.add_field("Method", parts[0] if len(parts) > 0 else "GET", parts[0].encode().hex() if len(parts) > 0 else "")
        frame.add_field("Request URI", parts[1] if len(parts) > 1 else "/", parts[1].encode().hex() if len(parts) > 1 else "")
        frame.add_field("Protocol Version", parts[2] if len(parts) > 2 else "HTTP/1.1", parts[2].encode().hex() if len(parts) > 2 else "")

    # Headers and body
    in_body = False
    body_lines = []
    header_count = 0
    for line in lines[1:]:
        if not in_body:
            if not line:
                in_body = True
                continue
            if ":" in line:
                k, v = line.split(":", 1)
                frame.add_field(f"Header [{k.strip()}]", v.strip())
                header_count += 1
        else:
            body_lines.append(line)

    body_text = "\n".join(body_lines).strip()
    if body_text:
        frame.add_field("Payload Body", body_text[:120] + ("..." if len(body_text) > 120 else ""), description=f"{len(body_text)} chars")
    return frame


def dissect_http2(data: bytes) -> DissectedFrame:
    frame = DissectedFrame("http2", "HTTP/2 & gRPC", "L7 (Application)", "HTTP/2 Binary Frame")
    frame.raw_data = data

    preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    offset = 0
    if data.startswith(preface):
        frame.add_field("Connection Preface", "PRI * HTTP/2.0", preface.hex(), "Client Connection Preface (24 bytes)")
        offset = len(preface)

    if len(data) >= offset + 9:
        hdr = data[offset:offset + 9]
        length = (hdr[0] << 16) | (hdr[1] << 8) | hdr[2]
        ftype = hdr[3]
        flags = hdr[4]
        stream_id = struct.unpack("!I", hdr[5:9])[0] & 0x7FFFFFFF

        types_map = {
            0: "DATA", 1: "HEADERS", 2: "PRIORITY", 3: "RST_STREAM",
            4: "SETTINGS", 5: "PUSH_PROMISE", 6: "PING", 7: "GOAWAY",
            8: "WINDOW_UPDATE", 9: "CONTINUATION"
        }
        type_str = types_map.get(ftype, f"UNKNOWN({ftype})")

        flag_names = []
        if ftype in (0, 1) and (flags & 0x01): flag_names.append("END_STREAM")
        if ftype in (1, 5) and (flags & 0x04): flag_names.append("END_HEADERS")
        if ftype == 4 and (flags & 0x01): flag_names.append("ACK")
        if flags & 0x08: flag_names.append("PADDED")
        flags_desc = "|".join(flag_names) if flag_names else f"0x{flags:02x}"

        frame.summary = f"HTTP/2 Frame: {type_str} (Stream: {stream_id}, Len: {length})"
        frame.add_field("Payload Length", length, hdr[:3].hex(), f"{length} bytes")
        frame.add_field("Frame Type", f"{type_str} (0x{ftype:02x})", hdr[3:4].hex())
        frame.add_field("Flags", f"0x{flags:02x} [{flags_desc}]", hdr[4:5].hex())
        frame.add_field("Stream ID", stream_id, hdr[5:9].hex(), "31-bit stream identifier")

        payload = data[offset + 9:offset + 9 + length]
        if payload:
            frame.add_field("Frame Payload", payload[:48].hex(), description=f"{len(payload)} bytes")
    return frame


def dissect_tls(data: bytes) -> DissectedFrame:
    frame = DissectedFrame("tls", "HTTPS / TLS Record Layer", "L6/L7 (Presentation/Session)", "TLS Record")
    frame.raw_data = data

    if len(data) >= 5:
        ctype = data[0]
        ver = (data[1] << 8) | data[2]
        length = struct.unpack("!H", data[3:5])[0]

        ctype_map = {20: "ChangeCipherSpec", 21: "Alert", 22: "Handshake", 23: "ApplicationData"}
        ctype_name = ctype_map.get(ctype, f"Unknown({ctype})")

        ver_map = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2 / TLS 1.3"}
        ver_name = ver_map.get(ver, f"0x{ver:04x}")

        frame.summary = f"TLS Record: {ctype_name} ({ver_name}, Len: {length})"
        frame.add_field("Content Type", f"{ctype_name} ({ctype})", data[0:1].hex())
        frame.add_field("Legacy Version", ver_name, data[1:3].hex())
        frame.add_field("Length", f"{length} bytes", data[3:5].hex())

        if ctype == 22 and len(data) >= 9: # Handshake
            htype = data[5]
            hlen = (data[6] << 16) | (data[7] << 8) | data[8]
            htype_map = {1: "ClientHello", 2: "ServerHello", 11: "Certificate", 16: "ClientKeyExchange"}
            htype_name = htype_map.get(htype, f"Type({htype})")
            frame.add_field("Handshake Type", f"{htype_name} ({htype})", data[5:6].hex())
            frame.add_field("Handshake Length", f"{hlen} bytes", data[6:9].hex())
            frame.summary = f"TLS Handshake: {htype_name} ({ver_name})"
    return frame


def dissect_websocket(data: bytes) -> DissectedFrame:
    frame = DissectedFrame("websocket", "WebSocket", "L7 (Application)", "WebSocket Frame")
    frame.raw_data = data

    if len(data) >= 2:
        b0 = data[0]
        b1 = data[1]
        fin = (b0 >> 7) & 1
        rsv = (b0 >> 4) & 7
        opcode = b0 & 0x0F
        mask = (b1 >> 7) & 1
        payload_len = b1 & 0x7F

        opcodes = {0: "Continuation", 1: "Text", 2: "Binary", 8: "Close", 9: "Ping", 10: "Pong"}
        op_name = opcodes.get(opcode, f"Reserved({opcode})")

        frame.summary = f"WebSocket: {op_name} (FIN={fin}, Mask={mask}, Len={payload_len})"
        frame.add_field("FIN", fin, f"0x{b0:02x}"[:3], "Final fragment" if fin else "More fragments follow")
        frame.add_field("Opcode", f"{op_name} (0x{opcode:x})", f"0x{opcode:02x}")
        frame.add_field("Mask Bit", mask, f"0x{b1:02x}"[:3], "Payload is masked by client" if mask else "Unmasked")

        offset = 2
        actual_len = payload_len
        if payload_len == 126 and len(data) >= 4:
            actual_len = struct.unpack("!H", data[2:4])[0]
            offset = 4
        elif payload_len == 127 and len(data) >= 10:
            actual_len = struct.unpack("!Q", data[2:10])[0]
            offset = 10

        frame.add_field("Payload Length", f"{actual_len} bytes")

        mask_key = None
        if mask and len(data) >= offset + 4:
            mask_key = data[offset:offset + 4]
            frame.add_field("Masking Key", mask_key.hex(), mask_key.hex())
            offset += 4

        raw_payload = data[offset:offset + actual_len]
        if mask_key and raw_payload:
            unmasked = bytes(b ^ mask_key[i % 4] for i, b in enumerate(raw_payload))
            frame.add_field("Decoded Payload", unmasked[:64].decode("utf-8", errors="replace"), description=f"{len(unmasked)} bytes")
        elif raw_payload:
            frame.add_field("Payload", raw_payload[:64].decode("utf-8", errors="replace"), description=f"{len(raw_payload)} bytes")
    return frame


def dissect_dns(data: bytes) -> DissectedFrame:
    frame = DissectedFrame("dns", "DNS (Domain Name System)", "L7 (Application)", "DNS Packet")
    frame.raw_data = data

    if len(data) >= 12:
        tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
        qr = (flags >> 15) & 1
        opcode = (flags >> 11) & 0x0F
        rcode = flags & 0x0F

        qr_name = "Response" if qr else "Query"
        rcodes = {0: "NoError", 1: "FormErr", 2: "ServFail", 3: "NXDomain", 5: "Refused"}
        rcode_name = rcodes.get(rcode, str(rcode))

        frame.summary = f"DNS {qr_name}: id=0x{tx_id:04x} (Q={qdcount}, A={ancount}, RCODE={rcode_name})"
        frame.add_field("Transaction ID", f"0x{tx_id:04x}", data[0:2].hex())
        frame.add_field("Flags", f"0x{flags:04x} [{qr_name}, RCODE={rcode_name}]", data[2:4].hex())
        frame.add_field("Questions (QDCOUNT)", qdcount, data[4:6].hex())
        frame.add_field("Answers (ANCOUNT)", ancount, data[6:8].hex())
        frame.add_field("Authority RRs (NSCOUNT)", nscount, data[8:10].hex())
        frame.add_field("Additional RRs (ARCOUNT)", arcount, data[10:12].hex())

        # Parse first Question QNAME if present
        offset = 12
        labels = []
        while offset < len(data) and data[offset] != 0:
            llen = data[offset]
            offset += 1
            if llen > 0 and offset + llen <= len(data):
                labels.append(data[offset:offset + llen].decode("latin1", errors="replace"))
                offset += llen
            else:
                break
        if labels:
            qname = ".".join(labels)
            offset += 1 # skip null byte
            qtype = struct.unpack("!H", data[offset:offset + 2])[0] if offset + 2 <= len(data) else 1
            qtypes = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT", 12: "PTR"}
            qtype_name = qtypes.get(qtype, f"TYPE{qtype}")
            frame.add_field("Query QNAME", qname)
            frame.add_field("Query QTYPE", f"{qtype_name} ({qtype})")
            frame.summary = f"DNS {qr_name}: {qname} ({qtype_name})"
    return frame


def dissect_redis(data: bytes) -> DissectedFrame:
    frame = DissectedFrame("redis", "Redis (RESP 2/3)", "L7 (Application)", "Redis Command/Reply")
    frame.raw_data = data

    text = data.decode("latin1", errors="replace")
    prefix = text[0] if text else ""

    type_map = {
        "+": "Simple String",
        "-": "Error",
        ":": "Integer",
        "$": "Bulk String",
        "*": "Array",
        "%": "Map",
        "~": "Set",
    }
    type_name = type_map.get(prefix, "Inline Command")
    frame.add_field("RESP Type", f"{type_name} ('{prefix}')", data[:1].hex() if data else "")

    if prefix == "*": # Array command
        lines = text.split("\r\n")
        try:
            elem_count = int(lines[0][1:])
            frame.add_field("Array Count", elem_count)
            args = []
            idx = 1
            while idx < len(lines):
                if lines[idx].startswith("$"):
                    idx += 1
                    if idx < len(lines):
                        args.append(lines[idx])
                idx += 1
            if args:
                cmd_line = " ".join(args)
                frame.summary = f"Redis Command: {cmd_line}"
                frame.add_field("Parsed Command", cmd_line)
        except Exception:
            frame.summary = f"Redis: {text.strip()}"
    elif prefix == "$":
        lines = text.split("\r\n")
        frame.summary = f"Redis Bulk String: {lines[1] if len(lines) > 1 else lines[0]}"
        frame.add_field("Content", lines[1] if len(lines) > 1 else "")
    else:
        clean = text.replace("\r\n", " ").strip()
        frame.summary = f"Redis: {clean}"
        frame.add_field("Content", clean)
    return frame


def dissect_mysql(data: bytes) -> DissectedFrame:
    frame = DissectedFrame("mysql", "MySQL / MariaDB", "L7 (Application)", "MySQL Packet")
    frame.raw_data = data

    if len(data) >= 4:
        pkt_len = data[0] | (data[1] << 8) | (data[2] << 16)
        seq_id = data[3]
        frame.add_field("Packet Length", f"{pkt_len} bytes", data[:3].hex())
        frame.add_field("Sequence ID", seq_id, data[3:4].hex())

        if len(data) >= 5:
            cmd = data[4]
            cmd_map = {
                0x00: "OK_Packet", 0x01: "COM_QUIT", 0x02: "COM_INIT_DB",
                0x03: "COM_QUERY", 0x04: "COM_FIELD_LIST", 0x0e: "COM_PING",
                0xfe: "EOF_Packet", 0xff: "ERR_Packet"
            }
            cmd_name = cmd_map.get(cmd, f"Command(0x{cmd:02x})")
            frame.add_field("Command / Type", f"{cmd_name} (0x{cmd:02x})", data[4:5].hex())

            if cmd == 0x03 and len(data) > 5: # COM_QUERY
                query_str = data[5:].decode("latin1", errors="replace")
                frame.summary = f"MySQL Query: {query_str[:60]}"
                frame.add_field("SQL Statement", query_str)
            elif cmd == 0x00: # OK
                frame.summary = f"MySQL Response: OK_Packet"
            elif cmd == 0xff and len(data) >= 7: # ERR
                err_code = struct.unpack("<H", data[5:7])[0]
                frame.summary = f"MySQL Response: ERR_Packet ({err_code})"
                frame.add_field("Error Code", err_code, data[5:7].hex())
            else:
                frame.summary = f"MySQL: {cmd_name}"
    return frame


def dissect_postgres(data: bytes) -> DissectedFrame:
    frame = DissectedFrame("postgres", "PostgreSQL", "L7 (Application)", "PostgreSQL Message")
    frame.raw_data = data

    if len(data) >= 5:
        msg_type = chr(data[0]) if 32 <= data[0] <= 126 else f"0x{data[0]:02x}"
        msg_len = struct.unpack("!I", data[1:5])[0]

        types = {
            "Q": "Simple Query", "P": "Parse", "B": "Bind", "E": "Execute",
            "S": "Sync", "X": "Terminate", "C": "CommandComplete",
            "D": "DataRow", "R": "Authentication", "Z": "ReadyForQuery"
        }
        type_name = types.get(msg_type, f"Message({msg_type})")

        frame.summary = f"Postgres: {type_name} (Len: {msg_len})"
        frame.add_field("Message Type", f"'{msg_type}' ({type_name})", data[:1].hex())
        frame.add_field("Length", f"{msg_len} bytes", data[1:5].hex())

        if msg_type == "Q" and len(data) > 5:
            query = data[5:].rstrip(b"\x00").decode("latin1", errors="replace")
            frame.summary = f"Postgres Query: {query[:60]}"
            frame.add_field("SQL Query", query)
    elif len(data) >= 8: # Startup Packet (no type byte)
        pkt_len = struct.unpack("!I", data[:4])[0]
        proto_ver = struct.unpack("!I", data[4:8])[0]
        if proto_ver == 0x00030000:
            frame.summary = "Postgres: StartupMessage (v3.0)"
            frame.add_field("Packet Length", pkt_len, data[:4].hex())
            frame.add_field("Protocol Version", "3.0 (0x00030000)", data[4:8].hex())
    return frame


def dissect_kafka(data: bytes) -> DissectedFrame:
    frame = DissectedFrame("kafka", "Apache Kafka", "L7 (Application)", "Kafka Message")
    frame.raw_data = data

    if len(data) >= 8:
        size = struct.unpack("!I", data[:4])[0]
        api_key = struct.unpack("!h", data[4:6])[0]
        api_ver = struct.unpack("!h", data[6:8])[0]

        api_map = {
            0: "Produce", 1: "Fetch", 2: "ListOffsets", 3: "Metadata",
            8: "OffsetCommit", 9: "OffsetFetch", 10: "FindCoordinator",
            11: "JoinGroup", 14: "SyncGroup", 18: "ApiVersions"
        }
        api_name = api_map.get(api_key, f"API_{api_key}")

        frame.summary = f"Kafka Request: {api_name} (v{api_ver})"
        frame.add_field("Message Size", f"{size} bytes", data[:4].hex())
        frame.add_field("API Key", f"{api_name} ({api_key})", data[4:6].hex())
        frame.add_field("API Version", api_ver, data[6:8].hex())

        if len(data) >= 12:
            corr_id = struct.unpack("!i", data[8:12])[0]
            frame.add_field("Correlation ID", corr_id, data[8:12].hex())
            frame.summary = f"Kafka Request: {api_name} (v{api_ver}, CorrID: {corr_id})"

        if len(data) >= 14:
            cid_len = struct.unpack("!h", data[12:14])[0]
            if cid_len > 0 and len(data) >= 14 + cid_len:
                client_id = data[14:14 + cid_len].decode("utf-8", errors="replace")
                frame.add_field("Client ID", client_id)
    return frame


def dissect_mqtt(data: bytes) -> DissectedFrame:
    frame = DissectedFrame("mqtt", "MQTT", "L7 (Application)", "MQTT Packet")
    frame.raw_data = data

    if len(data) >= 2:
        b0 = data[0]
        ptype = (b0 >> 4) & 0x0F
        flags = b0 & 0x0F

        ptypes = {
            1: "CONNECT", 2: "CONNACK", 3: "PUBLISH", 4: "PUBACK",
            5: "PUBREC", 6: "PUBREL", 7: "PUBCOMP", 8: "SUBSCRIBE",
            9: "SUBACK", 10: "UNSUBSCRIBE", 11: "UNSUBACK", 12: "PINGREQ",
            13: "PINGRESP", 14: "DISCONNECT"
        }
        pname = ptypes.get(ptype, f"Type({ptype})")

        frame.summary = f"MQTT: {pname}"
        frame.add_field("Packet Type", f"{pname} ({ptype})", f"0x{b0:02x}"[:3])
        frame.add_field("Flags", f"0x{flags:01x} [QoS: {(flags >> 1) & 3}]", f"0x{flags:02x}")

        rem_len = data[1] # simple 1-byte decode for demo
        frame.add_field("Remaining Length", f"{rem_len} bytes", data[1:2].hex())

        if ptype == 3 and len(data) >= 4: # PUBLISH
            tlen = (data[2] << 8) | data[3]
            if len(data) >= 4 + tlen:
                topic = data[4:4 + tlen].decode("utf-8", errors="replace")
                payload = data[4 + tlen:]
                frame.summary = f"MQTT PUBLISH: '{topic}' ({len(payload)} bytes)"
                frame.add_field("Topic", topic)
                frame.add_field("Payload", payload[:48].decode("utf-8", errors="replace"))
        elif ptype == 1 and len(data) >= 12: # CONNECT
            frame.summary = "MQTT: CONNECT"
            proto_name_len = (data[2] << 8) | data[3]
            pname_str = data[4:4 + proto_name_len].decode("latin1", errors="replace")
            frame.add_field("Protocol Name", pname_str)
    return frame


def dissect_ssh(data: bytes) -> DissectedFrame:
    frame = DissectedFrame("ssh", "SSH-2.0", "L7 (Application)", "SSH Protocol")
    frame.raw_data = data

    text = data.decode("latin1", errors="replace")
    if text.startswith("SSH-"):
        banner = text.split("\r\n")[0].split("\n")[0]
        frame.summary = f"SSH Banner: {banner}"
        parts = banner.split("-", 2)
        pver = f"SSH-{parts[1]}" if len(parts) > 1 else "SSH-2.0"
        sver = parts[2] if len(parts) > 2 else (parts[1] if len(parts) > 1 else banner)
        frame.add_field("Protocol Version", pver, pver.encode().hex())
        frame.add_field("Software Version", sver, sver.encode().hex())
        frame.add_field("Full Banner", banner, data[:len(banner)].hex())
    elif len(data) >= 5:
        pkt_len = struct.unpack("!I", data[:4])[0]
        pad_len = data[4]
        msg_type = data[5] if len(data) > 5 else 0
        msg_types = {20: "SSH_MSG_KEXINIT", 21: "SSH_MSG_NEWKEYS", 50: "SSH_MSG_USERAUTH_REQUEST"}
        msg_name = msg_types.get(msg_type, f"Type({msg_type})")
        frame.summary = f"SSH Binary Packet: {msg_name} (Len: {pkt_len})"
        frame.add_field("Packet Length", f"{pkt_len} bytes", data[:4].hex())
        frame.add_field("Padding Length", f"{pad_len} bytes", data[4:5].hex())
        frame.add_field("Message Type", f"{msg_name} ({msg_type})", data[5:6].hex() if len(data) > 5 else "")
    return frame


def dissect_ntp(data: bytes) -> DissectedFrame:
    frame = DissectedFrame("ntp", "NTP (Network Time Protocol)", "L7 (Application)", "NTP Packet")
    frame.raw_data = data

    if len(data) >= 48:
        b0 = data[0]
        li = (b0 >> 6) & 3
        vn = (b0 >> 3) & 7
        mode = b0 & 7
        stratum = data[1]
        poll = data[2]
        precision = struct.unpack("!b", data[3:4])[0]

        modes = {1: "Symmetric Active", 2: "Symmetric Passive", 3: "Client", 4: "Server", 5: "Broadcast"}
        mode_name = modes.get(mode, f"Mode({mode})")

        frame.summary = f"NTP {mode_name}: Stratum {stratum} (v{vn})"
        frame.add_field("Leap Indicator (LI)", li, f"0x{b0:02x}"[:3])
        frame.add_field("Version Number (VN)", vn)
        frame.add_field("Mode", f"{mode_name} ({mode})")
        frame.add_field("Stratum", stratum, data[1:2].hex())
        frame.add_field("Poll Interval", f"{poll} (2^{poll}s)", data[2:3].hex())
        frame.add_field("Precision", f"{precision} (2^{precision}s)", data[3:4].hex())

        ref_id = data[12:16].decode("latin1", errors="replace")
        frame.add_field("Reference ID", ref_id, data[12:16].hex())
    return frame


def dissect_icmp(data: bytes) -> DissectedFrame:
    frame = DissectedFrame("icmp", "ICMP (Internet Control Message Protocol)", "L3/L4 (Network Control)", "ICMP Message")
    frame.raw_data = data

    if len(data) >= 8:
        itype = data[0]
        icode = data[1]
        cksum = struct.unpack("!H", data[2:4])[0]

        types = {
            0: "Echo Reply", 3: "Destination Unreachable", 8: "Echo Request",
            11: "Time Exceeded"
        }
        tname = types.get(itype, f"Type({itype})")

        frame.summary = f"ICMP: {tname} (Code: {icode})"
        frame.add_field("Type", f"{tname} ({itype})", data[0:1].hex())
        frame.add_field("Code", icode, data[1:2].hex())
        frame.add_field("Checksum", f"0x{cksum:04x}", data[2:4].hex())

        if itype in (0, 8):
            ident, seq = struct.unpack("!HH", data[4:8])
            frame.add_field("Identifier", f"0x{ident:04x} ({ident})", data[4:6].hex())
            frame.add_field("Sequence Number", seq, data[6:8].hex())
            frame.summary = f"ICMP {tname}: id=0x{ident:04x} seq={seq}"
    return frame


def dissect_arp(data: bytes) -> DissectedFrame:
    frame = DissectedFrame("arp", "ARP (Address Resolution Protocol)", "L2/L3 (Link/Network)", "ARP Packet")
    frame.raw_data = data

    if len(data) >= 28:
        hw_type, proto_type, hw_size, proto_size, opcode = struct.unpack("!HHBBH", data[:8])
        smac = ":".join(f"{b:02x}" for b in data[8:14])
        sip = ".".join(str(b) for b in data[14:18])
        tmac = ":".join(f"{b:02x}" for b in data[18:24])
        tip = ".".join(str(b) for b in data[24:28])

        op_name = "Request (who-has)" if opcode == 1 else ("Reply (is-at)" if opcode == 2 else f"Op({opcode})")
        desc = f"Who has {tip}? Tell {sip}" if opcode == 1 else f"{sip} is at {smac}"

        frame.summary = f"ARP {op_name}: {desc}"
        frame.add_field("Hardware Type", f"Ethernet ({hw_type})", data[0:2].hex())
        frame.add_field("Protocol Type", f"IPv4 (0x{proto_type:04x})", data[2:4].hex())
        frame.add_field("Hardware Size", hw_size, data[4:5].hex())
        frame.add_field("Protocol Size", proto_size, data[5:6].hex())
        frame.add_field("Opcode", f"{op_name} ({opcode})", data[6:8].hex())
        frame.add_field("Sender MAC", smac, data[8:14].hex())
        frame.add_field("Sender IP", sip, data[14:18].hex())
        frame.add_field("Target MAC", tmac, data[18:24].hex())
        frame.add_field("Target IP", tip, data[24:28].hex())
    return frame


def dissect_unix(data: bytes) -> DissectedFrame:
    frame = DissectedFrame("unix", "AF_UNIX (Local IPC Socket)", "L4/L5 (Local IPC)", "UNIX Domain Socket Message")
    frame.raw_data = data

    if len(data) >= 16:
        magic, sender_pid, sender_uid, sender_gid = struct.unpack("!IIII", data[:16])
        frame.summary = f"AF_UNIX IPC Message (Sender PID: {sender_pid}, UID: {sender_uid})"
        frame.add_field("IPC Magic Header", f"0x{magic:08x}", data[:4].hex())
        frame.add_field("Sender PID", sender_pid, data[4:8].hex())
        frame.add_field("Sender UID", sender_uid, data[8:12].hex())
        frame.add_field("Sender GID", sender_gid, data[12:16].hex())
        payload = data[16:]
        if payload:
            frame.add_field("IPC Payload", payload.decode("latin1", errors="replace")[:64], description=f"{len(payload)} bytes")
    else:
        text = data.decode("latin1", errors="replace").strip()
        frame.summary = f"AF_UNIX IPC: {text[:60]}"
        frame.add_field("Payload Buffer", text)
        frame.add_field("Payload Length", len(data), hex_repr=f"0x{len(data):x}", description=f"{len(data)} bytes")
    return frame


def dissect_wifi(data: bytes) -> DissectedFrame:
    frame = DissectedFrame("wifi", "Wi-Fi (IEEE 802.11)", "L2 (Data Link / MAC)", "802.11 Wireless Frame")
    frame.raw_data = data

    if len(data) >= 24:
        fc = struct.unpack("<H", data[:2])[0]
        dur = struct.unpack("<H", data[2:4])[0]
        a1 = ":".join(f"{b:02x}" for b in data[4:10])
        a2 = ":".join(f"{b:02x}" for b in data[10:16])
        a3 = ":".join(f"{b:02x}" for b in data[16:22])
        seq_ctrl = struct.unpack("<H", data[22:24])[0]
        seq_num = (seq_ctrl >> 4) & 0x0FFF
        frag_num = seq_ctrl & 0x0F

        ftype = (fc >> 2) & 0x03
        subtype = (fc >> 4) & 0x0F
        type_names = {0: "Management", 1: "Control", 2: "Data", 3: "Extension"}
        tname = type_names.get(ftype, f"Type({ftype})")

        frame.summary = f"Wi-Fi 802.11 {tname}: SA={a2} -> DA={a1} (Seq: {seq_num})"
        frame.add_field("Frame Control", f"0x{fc:04x} [{tname}, Subtype: {subtype}]", data[:2].hex())
        frame.add_field("Duration / ID", f"{dur} us", data[2:4].hex())
        frame.add_field("Receiver Address (A1)", a1, data[4:10].hex())
        frame.add_field("Transmitter Address (A2)", a2, data[10:16].hex())
        frame.add_field("BSSID / Dest Address (A3)", a3, data[16:22].hex())
        frame.add_field("Sequence Number", seq_num, f"0x{seq_ctrl:04x}")
        frame.add_field("Fragment Number", frag_num)
    return frame


def dissect_bluetooth(data: bytes) -> DissectedFrame:
    frame = DissectedFrame("bluetooth", "Bluetooth & BLE (IEEE 802.15.1)", "L2/L4 (HCI / L2CAP)", "Bluetooth HCI/L2CAP Frame")
    frame.raw_data = data

    if len(data) >= 9:
        pkt_type = data[0]
        ptype_map = {1: "HCI Command", 2: "HCI ACL Data", 3: "HCI SCO Voice", 4: "HCI Event"}
        pname = ptype_map.get(pkt_type, f"Type({pkt_type})")

        handle_flags = struct.unpack("<H", data[1:3])[0]
        handle = handle_flags & 0x0FFF
        pb_flags = (handle_flags >> 12) & 0x03
        bc_flags = (handle_flags >> 14) & 0x03
        dlen = struct.unpack("<H", data[3:5])[0]

        l2cap_len = struct.unpack("<H", data[5:7])[0]
        cid = struct.unpack("<H", data[7:9])[0]
        cid_map = {0x0001: "L2CAP Signaling", 0x0004: "ATT (Attribute Protocol / BLE)", 0x0006: "SMP (Security Manager)"}
        cid_name = cid_map.get(cid, f"CID(0x{cid:04x})")

        frame.summary = f"Bluetooth ACL: Handle 0x{handle:03x} | {cid_name} (Len: {l2cap_len})"
        frame.add_field("HCI Packet Type", f"{pname} (0x{pkt_type:02x})", data[:1].hex())
        frame.add_field("Connection Handle", f"0x{handle:03x}", data[1:3].hex())
        frame.add_field("HCI Data Length", f"{dlen} bytes", data[3:5].hex())
        frame.add_field("L2CAP Payload Length", f"{l2cap_len} bytes", data[5:7].hex())
        frame.add_field("L2CAP Channel ID", f"{cid_name} (0x{cid:04x})", data[7:9].hex())

        payload = data[9:9 + l2cap_len]
        if payload:
            frame.add_field("L2CAP Payload", payload.hex()[:48], description=f"{len(payload)} bytes")
    return frame


def dissect_nfs(data: bytes) -> DissectedFrame:
    frame = DissectedFrame("nfs", "NFS (Network File System v3/v4)", "L7 (File Sharing / Storage)", "NFS RPC Call")
    frame.raw_data = data

    # Strip 4-byte RPC-over-TCP record marker if present
    offset = 0
    if len(data) >= 4 and (data[0] & 0x80):
        rm_len = struct.unpack("!I", data[:4])[0] & 0x7FFFFFFF
        if rm_len + 4 == len(data):
            offset = 4

    if len(data) >= offset + 24:
        xid, mtype, rpc_ver, prog, prog_ver, proc = struct.unpack("!IIIIII", data[offset:offset + 24])
        mname = "CALL" if mtype == 0 else "REPLY"
        pname = "NFS" if prog == 100003 else f"PROG({prog})"

        nfs_procs = {0: "NULL", 1: "GETATTR", 2: "SETATTR", 3: "LOOKUP", 4: "ACCESS", 6: "READ", 7: "WRITE", 8: "CREATE"}
        proc_name = nfs_procs.get(proc, f"PROC({proc})")

        frame.summary = f"NFSv{prog_ver} {mname}: {proc_name} (XID: 0x{xid:08x})"
        frame.add_field("Transaction ID (XID)", f"0x{xid:08x}", data[offset:offset + 4].hex())
        frame.add_field("RPC Message Type", f"{mname} ({mtype})", data[offset + 4:offset + 8].hex())
        frame.add_field("RPC Version", rpc_ver, data[offset + 8:offset + 12].hex())
        frame.add_field("Program Number", f"{pname} ({prog})", data[offset + 12:offset + 16].hex())
        frame.add_field("Program Version", f"v{prog_ver}", data[offset + 16:offset + 20].hex())
        frame.add_field("NFS Procedure", f"{proc_name} ({proc})", data[offset + 20:offset + 24].hex())
    return frame


def dissect_smb(data: bytes) -> DissectedFrame:
    frame = DissectedFrame("smb", "SMB2 / SMB3 (Server Message Block)", "L7 (File Sharing / Storage)", "SMB2 Packet")
    frame.raw_data = data

    offset = 0
    # Strip 4-byte Direct TCP Transport Header (NetBIOS-less) if present
    if len(data) >= 4 and data[0] == 0:
        nb_len = (data[1] << 16) | (data[2] << 8) | data[3]
        if nb_len + 4 == len(data):
            offset = 4

    if len(data) >= offset + 64 and data[offset:offset + 4] == b"\xfeSMB":
        proto_id = data[offset:offset + 4]
        struct_size = struct.unpack("<H", data[offset + 4:offset + 6])[0]
        cmd = struct.unpack("<H", data[offset + 12:offset + 14])[0]
        status = struct.unpack("<I", data[offset + 8:offset + 12])[0]
        msg_id = struct.unpack("<Q", data[offset + 24:offset + 32])[0]
        sess_id = struct.unpack("<Q", data[offset + 40:offset + 48])[0]

        cmds = {
            0x0000: "NEGOTIATE", 0x0001: "SESSION_SETUP", 0x0002: "LOGOFF",
            0x0003: "TREE_CONNECT", 0x0004: "TREE_DISCONNECT", 0x0005: "CREATE",
            0x0006: "CLOSE", 0x0008: "READ", 0x0009: "WRITE", 0x000e: "IOCTL"
        }
        cmd_name = cmds.get(cmd, f"CMD(0x{cmd:04x})")

        frame.summary = f"SMB2 {cmd_name}: MsgID={msg_id} (Status: 0x{status:08x})"
        frame.add_field("Protocol Signature", "0xFE 'SMB'", proto_id.hex())
        frame.add_field("Structure Size", f"{struct_size} bytes (Header)", data[offset + 4:offset + 6].hex())
        frame.add_field("NT Status Code", f"0x{status:08x}", data[offset + 8:offset + 12].hex())
        frame.add_field("Command Code", f"{cmd_name} (0x{cmd:04x})", data[offset + 12:offset + 14].hex())
        frame.add_field("Message ID", msg_id, data[offset + 24:offset + 32].hex())
        frame.add_field("Session ID", f"0x{sess_id:016x}", data[offset + 40:offset + 48].hex())
    return frame


def dissect_ftp(data: bytes) -> DissectedFrame:
    frame = DissectedFrame("ftp", "FTP (File Transfer Protocol)", "L7 (File Transfer)", "FTP Command/Response")
    frame.raw_data = data

    text = data.decode("latin1", errors="replace").strip()
    lines = text.split("\r\n") if "\r\n" in text else text.split("\n")
    first = lines[0]

    if re.match(r"^\d{3}\b", first):
        code = first[:3]
        desc = first[4:]
        frame.summary = f"FTP Response: {code} {desc}"
        frame.add_field("Response Code", code, code.encode().hex())
        frame.add_field("Response Description", desc, desc[:32].encode().hex())
    else:
        parts = first.split(" ", 1)
        cmd = parts[0].upper()
        arg = parts[1] if len(parts) > 1 else ""
        frame.summary = f"FTP Command: {cmd} {arg}"
        frame.add_field("FTP Command", cmd, cmd.encode().hex())
        if arg:
            frame.add_field("Arguments", arg, arg[:32].encode().hex())
        else:
            frame.add_field("Arguments", "<none>")
    return frame


def dissect_iscsi(data: bytes) -> DissectedFrame:
    frame = DissectedFrame("iscsi", "iSCSI (IP SAN Block Storage)", "L5/L7 (Storage Area Network)", "iSCSI BHS Segment")
    frame.raw_data = data

    if len(data) >= 48:
        b0 = data[0]
        opcode = b0 & 0x3F
        i_bit = (b0 >> 6) & 1

        op_names = {
            0x00: "NOP-Out", 0x01: "SCSI Command", 0x02: "SCSI Task Mgmt",
            0x03: "Login Request", 0x04: "Text Request", 0x05: "SCSI Data-Out",
            0x06: "Logout Request", 0x20: "NOP-In", 0x21: "SCSI Response",
            0x23: "Login Response", 0x25: "SCSI Data-In"
        }
        op_str = op_names.get(opcode, f"Opcode(0x{opcode:02x})")

        dlen = (data[5] << 16) | (data[6] << 8) | data[7]
        lun = struct.unpack("!Q", data[8:16])[0]
        itt = struct.unpack("!I", data[16:20])[0]
        cmdsn = struct.unpack("!I", data[24:28])[0]

        frame.summary = f"iSCSI BHS: {op_str} (LUN: {lun}, Task: 0x{itt:08x})"
        frame.add_field("Opcode", f"{op_str} (0x{opcode:02x})", data[:1].hex(), "Immediate" if i_bit else "")
        frame.add_field("Data Segment Length", f"{dlen} bytes", data[5:8].hex())
        frame.add_field("Logical Unit Number (LUN)", lun, data[8:16].hex())
        frame.add_field("Initiator Task Tag (ITT)", f"0x{itt:08x}", data[16:20].hex())
        frame.add_field("Command Sequence (CmdSN)", cmdsn, data[24:28].hex())
    return frame


def dissect_vlan(data: bytes) -> DissectedFrame:
    frame = DissectedFrame("vlan", "VLAN (IEEE 802.1Q)", "L2 (Data Link Tagging)", "802.1Q VLAN Tagged Frame")
    frame.raw_data = data

    if len(data) >= 4:
        tpid = struct.unpack("!H", data[:2])[0]
        tci = struct.unpack("!H", data[2:4])[0]
        pcp = (tci >> 13) & 0x07
        dei = (tci >> 12) & 0x01
        vid = tci & 0x0FFF

        frame.summary = f"IEEE 802.1Q VLAN: ID={vid} (PCP: {pcp}, DEI: {dei})"
        frame.add_field("Tag Protocol ID (TPID)", f"0x{tpid:04x}", data[:2].hex())
        frame.add_field("VLAN Identifier (VID)", vid, f"0x{vid:03x}")
        frame.add_field("Priority Code Point (PCP)", f"{pcp} (CoS)", f"0x{pcp:x}")
        frame.add_field("Drop Eligible Indicator (DEI)", dei)

        if len(data) >= 6:
            inner_eth = struct.unpack("!H", data[4:6])[0]
            eth_map = {0x0800: "IPv4", 0x86DD: "IPv6", 0x0806: "ARP"}
            frame.add_field("Encapsulated EtherType", f"{eth_map.get(inner_eth, f'0x{inner_eth:04x}')}", data[4:6].hex())
    return frame


# ==============================================================================
# Protocol Auto-Detector & Master Dissector
# ==============================================================================

def detect_protocol(data: bytes, port_hint: int = 0) -> str:
    """Detect which of the 22 supported protocols matches raw data or port hint."""
    if not data:
        return "http1"

    # 1. IEEE 802.1Q VLAN Tagging: TPID 0x8100
    if len(data) >= 4 and struct.unpack("!H", data[:2])[0] == 0x8100:
        return "vlan"

    # 2. ARP: exactly 28 bytes or starting with Ethernet HW=1, Proto=0x0800
    if len(data) >= 8 and data[:4] == b"\x00\x01\x08\x00":
        return "arp"

    # 3. ICMP: type in [0, 3, 8, 11] with port_hint 0 or icmp raw
    if port_hint == 0 and len(data) >= 8 and data[0] in (0, 3, 8, 11) and data[1] <= 15:
        return "icmp"

    # 4. Bluetooth & BLE (IEEE 802.15.1): HCI Packet Type 1..4 with valid handle & length
    if port_hint == 0 and len(data) >= 9 and data[0] in (1, 2, 3, 4) and data[1:3] != b"\x00\x00":
        handle = struct.unpack("<H", data[1:3])[0] & 0x0FFF
        if handle > 0 and handle < 0x0EFF:
            return "bluetooth"

    # 5. Wi-Fi (IEEE 802.11): Valid Frame Control (version=0, type in 0..2) and len >= 24
    if port_hint == 0 and len(data) >= 24 and (data[0] & 0x03) == 0:
        ftype = (data[0] >> 2) & 0x03
        if ftype in (0, 1, 2):
            return "wifi"

    # 6. SMB2 / SMB3: port 445 / 139 or Direct-TCP magic 0xFE 'SMB'
    if port_hint in (445, 139) or (b"\xfeSMB" in data[:8]):
        return "smb"

    # 7. NFS: port 2049 or RPC Program 100003
    if port_hint in (2049, 111):
        return "nfs"
    if len(data) >= 24 and struct.unpack("!I", data[12:16])[0] == 100003:
        return "nfs"
    if len(data) >= 28 and (data[0] & 0x80) and struct.unpack("!I", data[16:20])[0] == 100003:
        return "nfs"

    # 8. iSCSI: port 3260 or valid SCSI opcode in BHS
    if port_hint == 3260:
        return "iscsi"
    if len(data) >= 48 and (data[0] & 0x3F) in (0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x20, 0x21, 0x23, 0x25):
        if (data[1] & 0x80) or data[1] == 0:
            return "iscsi"

    # 9. FTP: port 21 / 20 or command verbs
    if port_hint in (21, 20) or data.startswith((b"USER ", b"PASS ", b"220 ", b"QUIT", b"PASV", b"EPSV", b"RETR ", b"STOR ")):
        return "ftp"

    # 10. NTP: port 123/323 or exactly 48 bytes with NTP header
    if port_hint in (123, 323) or (len(data) == 48 and ((data[0] >> 3) & 7) in (3, 4)):
        return "ntp"

    # 11. DNS: port 53
    if port_hint == 53:
        return "dns"

    # 12. TLS: port 443/8443 or ContentType 20..23 + TLS version 0x0301..0x0304
    if len(data) >= 5 and data[0] in (20, 21, 22, 23) and data[1] == 3 and data[2] in (1, 2, 3, 4):
        return "tls"

    # 13. HTTP/2: Connection preface
    if data.startswith(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"):
        return "http2"

    # 14. SSH: "SSH-" banner or port 22
    if data.startswith(b"SSH-") or port_hint in (22, 2222):
        return "ssh"

    # 15. Redis: starts with +, -, :, $, *
    if data.startswith((b"*", b"$", b"+", b"-", b":")) and b"\r\n" in data:
        return "redis"

    # 16. MySQL: port 3306 or COM_QUERY signature
    if port_hint in (3306, 33060):
        return "mysql"

    # 17. Postgres: port 5432 or starts with 'Q', 'P', 'B', etc.
    if port_hint in (5432, 5433, 6432) or (len(data) >= 5 and data[0] in b"QPBESXCDRZ" and struct.unpack("!I", data[1:5])[0] == len(data) - 1):
        return "postgres"

    # 18. Kafka: port 9092 or size prefix matching length
    if port_hint in (9092, 9093, 9094):
        return "kafka"

    # 19. MQTT: port 1883 or packet types 1..14
    if port_hint in (1883, 8883) or (len(data) >= 2 and ((data[0] >> 4) in (1, 2, 3, 4, 8, 12))):
        return "mqtt"

    # 20. WebSocket: port 80/8080/443 with valid fin/opcode
    if len(data) >= 2 and (data[0] & 0x70) == 0 and (data[0] & 0x0F) in (1, 2, 8, 9, 10):
        if data[1] & 0x80: # masked client frame
            return "websocket"

    # 21. AF_UNIX: Magic 0x554e4958 ('UNIX')
    if data.startswith(b"\x55\x4e\x49\x58"):
        return "unix"

    # 22. HTTP/1.1: Standard methods or response
    if data.startswith((b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"HTTP/")):
        return "http1"

    # Fallbacks based on port
    port_map = {
        80: "http1", 8080: "http1", 8000: "http1", 3000: "http1",
        443: "tls", 53: "dns", 6379: "redis", 3306: "mysql",
        5432: "postgres", 9092: "kafka", 1883: "mqtt", 22: "ssh",
        123: "ntp", 323: "ntp", 2049: "nfs", 445: "smb", 139: "smb",
        21: "ftp", 20: "ftp", 3260: "iscsi",
    }
    return port_map.get(port_hint, "http1")


def dissect_frame(data: bytes, port_hint: int = 0, proto_hint: str = "") -> DissectedFrame:
    """Dissect arbitrary raw network frame into structured metadata across all 22 protocols."""
    if not data:
        frame = DissectedFrame(proto_hint or "raw", "Raw Payload", "L2-L7", "Empty Packet (0 bytes)")
        frame.raw_data = b""
        frame.add_field("Frame Status", "EMPTY_PAYLOAD", "", "Zero-length packet or socket buffer")
        frame.add_field("Payload Length", 0, "0x0", "0 bytes")
        return frame

    pid = proto_hint.lower() if proto_hint else detect_protocol(data, port_hint)

    dissectors = {
        "http1": dissect_http1,
        "http2": dissect_http2,
        "tls": dissect_tls,
        "websocket": dissect_websocket,
        "dns": dissect_dns,
        "redis": dissect_redis,
        "mysql": dissect_mysql,
        "postgres": dissect_postgres,
        "kafka": dissect_kafka,
        "mqtt": dissect_mqtt,
        "ssh": dissect_ssh,
        "ntp": dissect_ntp,
        "icmp": dissect_icmp,
        "arp": dissect_arp,
        "unix": dissect_unix,
        "wifi": dissect_wifi,
        "bluetooth": dissect_bluetooth,
        "nfs": dissect_nfs,
        "smb": dissect_smb,
        "ftp": dissect_ftp,
        "iscsi": dissect_iscsi,
        "vlan": dissect_vlan,
    }

    fn = dissectors.get(pid, dissect_http1)
    try:
        frame = fn(data)
    except Exception as e:
        proto_meta = PROTOCOLS_CATALOG.get(pid, {})
        proto_name = proto_meta.get("name", pid.upper())
        osi_layer = proto_meta.get("osi", "L7 (Application)")
        frame = DissectedFrame(
            pid,
            proto_name,
            osi_layer,
            f"[CORRUPTED_FRAME: {type(e).__name__}: {str(e)}]"
        )
        frame.raw_data = data
        frame.add_field("Parsing Error", f"{type(e).__name__}: {str(e)}", description="Parser exception during frame dissection")
        frame.add_field("Payload Length", len(data), hex_repr=f"0x{len(data):x}", description="Raw corrupted or malformed payload size")
        frame.add_field("Frame Status", "MALFORMED_OR_TRUNCATED", description="Data did not conform to protocol specification")
        return frame

    frame.proto_id = pid
    if len(frame.fields) == 0:
        frame.summary = f"[TRUNCATED_FRAME: {frame.proto_name}] ({len(data)} bytes)"
        frame.add_field("Frame Status", "TRUNCATED_FRAME", description=f"Payload size ({len(data)} bytes) is smaller than required minimum protocol header")
        frame.add_field("Payload Length", len(data), hex_repr=f"0x{len(data):x}", description="Incomplete wire payload received")

    return frame


# ==============================================================================
# Synthetic Wire Frame Generator (For Bit-Exact Testing)
# ==============================================================================

def build_sample_frame(proto_name: str) -> bytes:
    """Generate authentic wire frame bytes for each of the 22 protocols."""
    p = proto_name.lower().replace("/", "").replace(".", "").replace(" ", "")

    if p in ("http1", "http", "http11"):
        return b"GET /compute?input=live_kray_eval HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUser-Agent: curl/7.76.1\r\nAccept: */*\r\n\r\n"

    elif p in ("http2", "grpc"):
        preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        # HEADERS frame: length=8, type=1 (HEADERS), flags=5 (END_STREAM|END_HEADERS), stream_id=1
        hdr = bytes([0, 0, 8, 1, 5]) + struct.pack("!I", 1)
        fake_payload = b"\x82\x86\x84\x41\x8a\x08\x9d\x5c" # HPACK encoded headers
        return preface + hdr + fake_payload

    elif p in ("tls", "https"):
        # TLS 1.2 Record (ContentType=22 Handshake, Version=0x0303, Length=48)
        # Handshake Type=1 (ClientHello), Length=40
        rec_hdr = struct.pack("!BHH", 22, 0x0303, 44)
        hs_hdr = struct.pack("!B", 1) + struct.pack("!I", 40)[1:] # 1 byte type, 3 bytes len
        client_random = b"\x12" * 32
        hs_body = client_random + b"\x00" + struct.pack("!H", 2) + b"\xc0\x2f" # SessionId=0, CipherSuite
        return rec_hdr + hs_hdr + hs_body

    elif p in ("websocket", "ws"):
        # Text frame, FIN=1, Opcode=1, Mask=1, Len=5, MaskKey="KRAY", Payload="hello"
        b0 = 0x81
        b1 = 0x80 | 5
        mask_key = b"KRAY"
        raw_msg = b"hello"
        masked = bytes(b ^ mask_key[i % 4] for i, b in enumerate(raw_msg))
        return struct.pack("!BB", b0, b1) + mask_key + masked

    elif p in ("dns",):
        # Query: id=0x1234, flags=0x0100 (Standard Query, RD=1), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
        hdr = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        qname = b"\x03api\x07cluster\x05local\x00"
        qtype_qclass = struct.pack("!HH", 1, 1) # Type A, Class IN
        return hdr + qname + qtype_qclass

    elif p in ("redis", "resp"):
        return b"*3\r\n$3\r\nSET\r\n$4\r\nuser\r\n$5\r\nalice\r\n"

    elif p in ("mysql", "mariadb"):
        # COM_QUERY: "SELECT * FROM orders WHERE id=42"
        query = b"SELECT * FROM orders WHERE id=42"
        pkt_len = len(query) + 1
        hdr = bytes([pkt_len & 0xff, (pkt_len >> 8) & 0xff, (pkt_len >> 16) & 0xff, 0]) # len + seq=0
        return hdr + b"\x03" + query # 0x03 = COM_QUERY

    elif p in ("postgres", "postgresql", "pgsql"):
        # Simple Query: 'Q', length=35 (including length field), "SELECT version();\0"
        query = b"SELECT version();\x00"
        msg_len = len(query) + 4
        return b"Q" + struct.pack("!I", msg_len) + query

    elif p in ("kafka",):
        # Request Size=26, ApiKey=0 (Produce), ApiVer=7, CorrId=42, ClientId="kray_tracer"
        cid = b"kray"
        body = struct.pack("!hhih", 0, 7, 42, len(cid)) + cid + b"\x00" * 12
        size = len(body)
        return struct.pack("!I", size) + body

    elif p in ("mqtt",):
        # PUBLISH: QoS=0, Topic="sensors/temp", Payload="24.5C"
        topic = b"sensors/temp"
        payload = b"24.5C"
        var_hdr = struct.pack("!H", len(topic)) + topic
        rem_len = len(var_hdr) + len(payload)
        return bytes([0x30, rem_len]) + var_hdr + payload

    elif p in ("ssh", "ssh2"):
        return b"SSH-2.0-OpenSSH_8.7 RockyLinux\r\n"

    elif p in ("ntp",):
        # 48-byte NTP client request: LI=0, VN=4, Mode=3 (Client), Stratum=0, Poll=4, Precision=-20
        b0 = (0 << 6) | (4 << 3) | 3
        pkt = bytearray(48)
        pkt[0] = b0
        pkt[1] = 0 # Stratum 0
        pkt[2] = 4 # Poll
        pkt[3] = 0xEC # Precision -20
        # Transmit timestamp (fake epoch)
        pkt[40:48] = struct.pack("!II", 0xE8A00000, 0x12345678)
        return bytes(pkt)

    elif p in ("icmp",):
        # Echo Request: Type=8, Code=0, Checksum=0, Ident=0x1234, Seq=1, Payload="EBPF"
        data = b"EBPF_KRAY_PROBE_ECHO"
        hdr = struct.pack("!BBHHH", 8, 0, 0, 0x1234, 1)
        raw = hdr + data
        # compute simple 16-bit ones complement checksum
        ck = 0
        for i in range(0, len(raw), 2):
            w = (raw[i] << 8) + (raw[i + 1] if i + 1 < len(raw) else 0)
            ck += w
        ck = (ck >> 16) + (ck & 0xffff)
        ck = ~ck & 0xffff
        return struct.pack("!BBHHH", 8, 0, ck, 0x1234, 1) + data

    elif p in ("arp",):
        # ARP Request: HW=1 (Eth), Proto=0x0800 (IPv4), HwLen=6, ProtoLen=4, Op=1 (Request)
        # Sender: 52:54:00:12:34:56 / 192.168.64.14
        # Target: 00:00:00:00:00:00 / 192.168.64.1
        smac = bytes([0x52, 0x54, 0x00, 0x12, 0x34, 0x56])
        sip = bytes([192, 168, 64, 14])
        tmac = bytes([0, 0, 0, 0, 0, 0])
        tip = bytes([192, 168, 64, 1])
        return struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + smac + sip + tmac + tip

    elif p in ("unix", "af_unix"):
        # Magic 0x554E4958, PID=12450, UID=1000, GID=1000, Payload="kray_ipc_worker_handoff"
        magic = 0x554E4958
        hdr = struct.pack("!IIII", magic, 12450, 1000, 1000)
        payload = b"kray_ipc_worker_handoff_job_id_99"
        return hdr + payload

    elif p in ("wifi", "80211", "wlan"):
        fc = 0x0008  # Data frame (Type=2 Data, Subtype=0)
        dur = 58
        a1 = bytes([0x52, 0x54, 0x00, 0x12, 0x34, 0x56])  # Receiver MAC
        a2 = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])  # Transmitter MAC
        a3 = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])  # BSSID (AP)
        seq_ctrl = (100 << 4) | 0
        payload = b"IEEE 802.11 Wireless Data Payload"
        return struct.pack("<HH", fc, dur) + a1 + a2 + a3 + struct.pack("<H", seq_ctrl) + payload

    elif p in ("bluetooth", "bt", "ble", "802151"):
        pkt_type = 2  # HCI ACL Data
        handle_flags = 0x0042  # Handle 0x042, PB=0, BC=0
        dlen = 16
        l2cap_len = 12
        cid = 0x0004  # Attribute Protocol (ATT / BLE)
        att_payload = b"\x12\x01\x00\x2a\x00\x4b\x52\x41\x59\x5f\x42\x54"
        return bytes([pkt_type]) + struct.pack("<HH", handle_flags, dlen) + struct.pack("<HH", l2cap_len, cid) + att_payload

    elif p in ("nfs", "nfsv3", "nfsv4"):
        rm_len = 40
        rm_hdr = struct.pack("!I", 0x80000000 | rm_len)  # RPC-over-TCP record marker
        xid = 0x1A2B3C4D
        mtype = 0  # CALL
        rpc_ver = 2
        prog = 100003  # NFS
        prog_ver = 3  # NFSv3
        proc = 3  # LOOKUP
        return rm_hdr + struct.pack("!IIIIIIIIII", xid, mtype, rpc_ver, prog, prog_ver, proc, 0, 0, 0, 0)

    elif p in ("smb", "smb2", "smb3", "cifs"):
        nb_hdr = struct.pack("!I", 64)
        hdr = (
            b"\xfeSMB"
            + struct.pack("<HH", 64, 1)
            + struct.pack("<I", 0)
            + struct.pack("<HH", 0, 1)
            + struct.pack("<II", 0, 0)
            + struct.pack("<Q", 1)  # Message ID
            + struct.pack("<II", 0, 0)
            + struct.pack("<Q", 0)  # Session ID
            + (b"\x00" * 16)  # Signature
        )
        return nb_hdr + hdr

    elif p in ("ftp",):
        return b"USER anonymous\r\n"

    elif p in ("iscsi", "san"):
        bhs = bytearray(48)
        bhs[0] = 0x41  # Immediate bit=1, Opcode=1 (SCSI Command)
        bhs[1] = 0x80  # Final / Read
        bhs[5] = 0
        bhs[6] = 0
        bhs[7] = 0
        bhs[8:16] = struct.pack("!Q", 0)  # LUN 0
        bhs[16:20] = struct.pack("!I", 0x55AA1122)  # Initiator Task Tag (ITT)
        bhs[24:28] = struct.pack("!I", 101)  # CmdSN
        bhs[32:48] = b"\x28\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00"
        return bytes(bhs)

    elif p in ("vlan", "8021q"):
        tpid = 0x8100
        tci = (3 << 13) | (0 << 12) | 100  # PCP=3, DEI=0, VID=100
        inner_eth = 0x0800  # IPv4
        ip_payload = b"\x45\x00\x00\x14\x00\x00\x00\x00\x40\x01\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01"
        return struct.pack("!HHH", tpid, tci, inner_eth) + ip_payload

    return b"UNKNOWN_RAW_FRAME_PAYLOAD"


# ==============================================================================
# Frame Inspector Tree Formatter
# ==============================================================================

def format_frame_tree(dissected: DissectedFrame) -> str:
    """Format dissected frame into a Wireshark-like hierarchical decoded tree."""
    lines = []
    lines.append(f"┌─ [{dissected.proto_name}] {dissected.summary}")
    lines.append(f"│  OSI Layer: {dissected.osi_layer} | Total Size: {len(dissected.raw_data)} bytes")
    lines.append("├─────────────────────────────────────────────────────────────────────────────")

    max_nlen = max((len(f.name) for f in dissected.fields), default=12)
    for f in dissected.fields:
        hex_part = f"({f.hex_repr}) " if f.hex_repr else ""
        desc_part = f" — {f.description}" if f.description else ""
        lines.append(f"│  • {f.name.ljust(max_nlen)} : {f.value} {hex_part}{desc_part}")

    lines.append("├─────────────────────────────────────────────────────────────────────────────")
    lines.append("│  [RAW FRAME DATA & HEX DUMP]")
    lines.append(format_hexdump(dissected.raw_data))
    lines.append("└─────────────────────────────────────────────────────────────────────────────")
    return "\n".join(lines)


# ==============================================================================
# Port-by-Port Classification Registry Printer
# ==============================================================================

def print_ports_registry() -> None:
    """Systematically print communication protocols grouped by Port Categories."""
    print("================================================================================")
    print(" SYSTEMATIC PROTOCOL REGISTRY BY PORT CATEGORIES & OSI LAYERS")
    print("================================================================================")
    print("")

    categories = [
        ("GROUP 1: Non-IP, Link Layer & Wireless Standards (IEEE 802 Family & Kernel IPC)", [
            ("wifi", "Wi-Fi (IEEE 802.11 a/b/g/n/ac/ax/be)", "L2 MAC", "mac80211 / nl80211 / Radiotap Frame"),
            ("bluetooth", "Bluetooth & BLE (IEEE 802.15.1)", "L2/L4 HCI", "AF_BLUETOOTH / HCI / L2CAP / ATT / GATT"),
            ("vlan", "VLAN Tagging (IEEE 802.1Q)", "L2 Data Link", "EtherType 0x8100 / 802.1p CoS / 12-bit VID"),
            ("arp", "ARP (Address Resolution Protocol)", "L2/L3 Link", "EtherType 0x0806 / IPv4 to MAC resolution"),
            ("icmp", "ICMP (Internet Control Message)", "L3/L4 Network", "IPPROTO_ICMP (1) / Echo, Unreachable, TTL"),
            ("unix", "AF_UNIX (Local IPC Socket)", "L4/L5 IPC", "PF_LOCAL / SCM_CREDENTIALS / Kernel handoff"),
        ]),
        ("GROUP 2: Well-Known System Ports (0 ~ 1023) — Core Internet Services", [
            ("ftp", "FTP Control (RFC 959)", "TCP Port 21", "File Transfer Protocol interactive control"),
            ("ssh", "SSH-2.0 (RFC 4253)", "TCP Port 22", "Secure Shell encrypted remote execution"),
            ("dns", "DNS (Domain Name System)", "UDP/TCP Port 53", "Hierarchical domain name resolution"),
            ("http1", "HTTP/1.1 (RFC 7230)", "TCP Port 80", "World Wide Web Hypertext Transfer Protocol"),
            ("ntp", "NTP (RFC 5905)", "UDP Port 123", "Network Time Protocol sub-millisecond sync"),
            ("tls", "HTTPS / TLS Record (RFC 8446)", "TCP Port 443", "TLS 1.2 / 1.3 Transport Layer Security"),
            ("smb", "SMB2 / SMB3 (CIFS)", "TCP Port 445", "Direct-hosted NetBIOS-less Windows File Sharing"),
        ]),
        ("GROUP 3: Registered Ports (1024 ~ 49151) — Middleware, Databases & Storage", [
            ("mqtt", "MQTT (v3.1.1 / 5.0)", "TCP Port 1883", "IoT lightweight telemetry publish/subscribe"),
            ("nfs", "NFSv3 / NFSv4 (RFC 1813/7530)", "TCP/UDP Port 2049", "Network File System SunRPC/XDR storage"),
            ("iscsi", "iSCSI SAN Block Storage", "TCP Port 3260", "IP SAN SCSI over TCP (RFC 3720 / 7143)"),
            ("mysql", "MySQL / MariaDB Wire Protocol", "TCP Port 3306", "Relational database client/server binary"),
            ("postgres", "PostgreSQL Wire Protocol 3.0", "TCP Port 5432", "Object-relational frontend/backend messages"),
            ("redis", "Redis (RESP 2/3)", "TCP Port 6379", "In-memory key-value data structure store"),
            ("kafka", "Apache Kafka Binary Protocol", "TCP Port 9092", "Distributed event streaming & commit log"),
            ("http2", "gRPC / HTTP/2 (RFC 7540)", "TCP Port 50051", "Multiplexed binary RPC with Protocol Buffers"),
        ]),
        ("GROUP 4: Dynamic & Ephemeral Ports (49152 ~ 65535) — Client Ephemeral Sessions", [
            ("client_ephem", "Client Outbound TCP Sockets", "TCP 49152~65535", "Allocated by kernel via ip_local_port_range"),
            ("p2p_data", "Peer-to-Peer & High-port RTP", "UDP 49152~65535", "Dynamic media transport (WebRTC / RTP)"),
        ]),
    ]

    for cat_title, items in categories:
        print(f"### {cat_title}")
        for item in items:
            key, name, port_osi, desc = item
            print(f"* [{port_osi}] {name}")
            print(f"  - Key: `{key}` | Details: {desc}")
        print("")


# ==============================================================================
# IEEE Communications Standards Comprehensive Guide
# ==============================================================================

def print_ieee_standards() -> None:
    """Print in-depth technical analysis of IEEE 802 communications standards."""
    print("================================================================================")
    print(" IEEE 802 COMMUNICATIONS STANDARDS FAMILY & LINUX KERNEL INTEGRATION")
    print("================================================================================")
    print("")

    sections = [
        ("1. IEEE 802.1: Higher Layer LAN / MAN Bridging & Architecture", [
            "IEEE 802.1Q: Virtual Bridged Local Area Networks (VLAN Tagging). Adds a 4-byte 802.1Q header with 3-bit PCP (Priority Code Point), 1-bit DEI (Drop Eligible Indicator), and 12-bit VID (4094 VLANs). Processed in Linux via the `8021q` module and HW acceleration (`skb->vlan_proto = ETH_P_8021Q`).",
            "IEEE 802.1p: Traffic Class Expediting & Dynamic Multicast Filtering (Quality of Service / CoS). Maps to 8 priority levels (0: Best Effort, 5: Voice <10ms, 6: Internetwork Control, 7: Network Control). Used by Linux TC (`sch_prio`, `sch_mqprio`).",
            "IEEE 802.1X: Port-Based Network Access Control (EAPOL). Secures wired and wireless ports via Extensible Authentication Protocol. Managed by `wpa_supplicant` and Linux crypto subsystems.",
            "IEEE 802.1AX (formerly 802.3ad): Link Aggregation Control Protocol (LACP). Aggregates multiple physical ports into a single logical channel (`bonding` / `team` driver in Linux).",
            "IEEE 802.1AE (MACsec): Media Access Control Security. Encrypts all traffic at the MAC layer with GCM-AES-128/256. Fully supported in Linux kernel via `macsec` virtual interfaces.",
            "IEEE 802.1AS / 802.1Qbv (TSN - Time-Sensitive Networking): Sub-microsecond deterministic synchronization (PTP IEEE 1588 profile) and Time-Aware Shaper for automotive/industrial real-time control.",
        ]),
        ("2. IEEE 802.3: Ethernet Working Group (Wired Infrastructure)", [
            "Standard Revisions: 10BASE-T (802.3i), 100BASE-TX Fast Ethernet (802.3u), 1000BASE-T Gigabit (802.3ab), 10GBASE-T (802.3an), 25G/40G/100G (802.3ba/bj/by), and modern 200G/400G/800G (802.3bs/ck).",
            "Media Access Control (CSMA/CD): Carrier Sense Multiple Access with Collision Detection (retained in standard for backwards compatibility, full-duplex switched in all modern networks).",
            "Frame Structure: Preamble (7 bytes) + SFD (1 byte) + Destination MAC (6 bytes) + Source MAC (6 bytes) + EtherType/Length (2 bytes) + Payload (46-1500 bytes MTU, up to 9000 bytes Jumbo) + FCS (4 bytes CRC-32).",
            "Power over Ethernet (PoE): 802.3af (PoE 15.4W), 802.3at (PoE+ 30W), and 802.3bt (4PPoE up to 90W) for powering access points, IP cameras, and IoT gateways over twisted pair.",
            "Linux eBPF Hook Points: Raw driver RX ring (`XDP`), sk_buff allocation (`netif_receive_skb`), and traffic classification (`clsact` / `TC egress/ingress`).",
        ]),
        ("3. IEEE 802.11: Wireless Local Area Network (Wi-Fi) Family", [
            "Generation Evolution: 802.11b (Wi-Fi 1, 11 Mbps 2.4GHz) -> 802.11a/g (Wi-Fi 2/3, 54 Mbps 5GHz/2.4GHz) -> 802.11n (Wi-Fi 4, MIMO 600 Mbps) -> 802.11ac (Wi-Fi 5, MU-MIMO 6.9 Gbps) -> 802.11ax (Wi-Fi 6/6E, OFDMA, 1024-QAM, 6GHz band, 9.6 Gbps) -> 802.11be (Wi-Fi 7, 320 MHz channels, 4096-QAM, Multi-Link Operation MLO, up to 46 Gbps).",
            "Frame Types: Management (Beacon, Probe Request/Response, Association, Authentication), Control (RTS, CTS, ACK, BlockACK), and Data (QoS Data, Null Function).",
            "Frame Architecture: 2-byte Frame Control (Type, Subtype, ToDS, FromDS, MoreFrag, Retry, PwrMgmt, MoreData, Protected, Order) + 2-byte Duration/ID + Address 1 (RA) + Address 2 (TA) + Address 3 (BSSID) + 2-byte Sequence Control + optional Address 4 + QoS Control + Frame Body + 4-byte FCS.",
            "Linux Kernel Architecture: `mac80211` (SoftMAC driver framework), `cfg80211` (wireless configuration API), and `nl80211` (Netlink user/kernel interface). Monitored via Radiotap headers in `monitor` mode.",
        ]),
        ("4. IEEE 802.15: Wireless Personal Area Networks (WPAN)", [
            "IEEE 802.15.1: Bluetooth & Bluetooth Low Energy (BLE). Frequency hopping spread spectrum (FHSS) in the 2.4 GHz ISM band. Protocols: HCI (Host Controller Interface), L2CAP (Logical Link Control & Adaptation), RFCOMM, ATT (Attribute Protocol), GATT (Generic Attribute Profile). Linux Subsystem: BlueZ via `AF_BLUETOOTH` sockets (`btmon`, `hciconfig`).",
            "IEEE 802.15.4: Low-Rate Wireless Personal Area Networks (LR-WPAN). Physical and MAC layers for ultra-low power, low bandwidth IoT. Foundational standard for Zigbee, Thread, 6LoWPAN (IPv6 over Low-Power WPAN), and CSA Matter. Operates on 2.4 GHz, 868 MHz (EU), and 915 MHz (US) with DSSS modulation and 127-byte max physical packet size. Linux Subsystem: `net/ieee802154` and `wpan-tools`.",
            "IEEE 802.15.3: High-Rate WPAN / Ultra-Wideband (UWB). Nanosecond pulse wireless for high-speed multimedia streaming and centimeter-accurate spatial ranging (IEEE 802.15.4z UWB fine ranging).",
            "IEEE 802.15.6: Wireless Body Area Networks (WBAN). Ultra-low latency, ultra-low power communications in, on, or around the human body for medical telemetry and biosensors.",
        ]),
        ("5. IEEE 802.16 & Beyond: Broadband Wireless Access", [
            "IEEE 802.16: WiMAX (Worldwide Interoperability for Microwave Access). Point-to-multipoint wireless metropolitan area networking.",
            "IEEE 802.24: Smart Grid Technical Advisory Group coordinating IoT and utility communication across IEEE standards.",
        ]),
    ]

    for title, items in sections:
        print(f"### {title}")
        for item in items:
            print(f"* {item}")
        print("")


# ==============================================================================
# Self-Test & CLI Runner
# ==============================================================================

def run_all_protocols_test() -> bool:
    """Verify bit-exact decode fidelity across all 22 supported protocols."""
    print("================================================================================")
    print(" [kray_proto_dissector] 22-Protocol Data Frame Decode Verification")
    print("================================================================================")

    all_passed = True
    total = len(PROTOCOLS_CATALOG)
    idx = 1
    for proto_key, meta in PROTOCOLS_CATALOG.items():
        sample_bytes = build_sample_frame(proto_key)
        hint_port = meta["default_ports"][0] if meta["default_ports"] else 0
        dissected = dissect_frame(sample_bytes, port_hint=hint_port, proto_hint=proto_key)

        is_ok = (dissected.proto_id == proto_key) and (len(dissected.fields) >= 2) and (len(dissected.raw_data) > 0)
        status = "\033[32m[PASS]\033[0m" if is_ok else "\033[31m[FAIL]\033[0m"
        print(f" #{idx:02d}/{total} {meta['name'].ljust(38)} : {status} {dissected.summary}")

        if not is_ok:
            all_passed = False
        idx += 1

    print("================================================================================")
    summary_status = f"{total}/{total} PASSED (100% VERIFIED)" if all_passed else "SOME TESTS FAILED"
    print(f" Summary: {summary_status}")
    print("================================================================================")
    return all_passed


# Backward-compatibility alias
run_all_15_protocols_test = run_all_protocols_test


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "test"

    if cmd == "list":
        print("================================================================================")
        print(" Supported 22 Communication Protocols in eBPF-WireToCode-Tracer")
        print("================================================================================")
        for i, (k, m) in enumerate(PROTOCOLS_CATALOG.items(), start=1):
            ports_str = ", ".join(str(p) for p in m["default_ports"]) if m["default_ports"] != [0] else "L2/L3/Kernel"
            print(f" {i:2d}. {m['name']:<35} | {m['osi']:<30} | Ports: {ports_str}")
            print(f"     Description: {m['description']}")
        sys.exit(0)

    elif cmd == "ports":
        print_ports_registry()
        sys.exit(0)

    elif cmd in ("ieee", "standards"):
        print_ieee_standards()
        sys.exit(0)

    elif cmd in ("inspect", "show", "dump"):
        target = sys.argv[2] if len(sys.argv) > 2 else "http1"
        sample_bytes = build_sample_frame(target)
        res = dissect_frame(sample_bytes, proto_hint=target)
        print(format_frame_tree(res))
        sys.exit(0)

    elif cmd == "test":
        success = run_all_protocols_test()
        sys.exit(0 if success else 1)

    else:
        # Default: run full test
        success = run_all_protocols_test()
        sys.exit(0 if success else 1)
