"""Minimal ClientHello SNI extract from raw TCP bytes (no PyShark required)."""

from __future__ import annotations


def extract_tls_sni_from_payload(payload: bytes) -> str | None:
    """
    Best-effort parse of Server Name Indication in TLS ClientHello.
    Tolerant of fragmentation; may return None.
    """
    if len(payload) < 43 or payload[0] != 0x16:  # not handshake
        return None
    # walk simple structure: record -> handshake -> client hello -> extensions
    try:
        i = 5  # start of handshake
        if i >= len(payload) or payload[i] != 0x01:  # client hello
            return None
        # skip handshake header + version + random + session id
        i += 4
        if i + 2 > len(payload):
            return None
        hs_len = int.from_bytes(payload[i - 3 : i], "big")
        ch_start = i - 1
        i = ch_start + 4
        if i + 34 > len(payload):
            return None
        i += 34  # random
        sid_len = payload[i]
        i += 1 + sid_len
        if i + 2 > len(payload):
            return None
        cs_len = int.from_bytes(payload[i : i + 2], "big")
        i += 2 + cs_len
        if i + 1 > len(payload):
            return None
        comp_len = payload[i]
        i += 1 + comp_len
        if i + 2 > len(payload):
            return None
        ext_len = int.from_bytes(payload[i : i + 2], "big")
        i += 2
        end = i + ext_len
        while i + 4 <= end and i < len(payload):
            et = int.from_bytes(payload[i : i + 2], "big")
            el = int.from_bytes(payload[i + 2 : i + 4], "big")
            i += 4
            block = payload[i : i + el]
            if et == 0:  # server_name
                if len(block) < 2:
                    return None
                nlen = int.from_bytes(block[0:2], "big")
                k = 2
                while k < 2 + nlen and k < len(block):
                    t = block[k]
                    l = int.from_bytes(block[k + 1 : k + 3], "big")
                    if t == 0 and l > 0 and k + 3 + l <= len(block):
                        name = block[k + 3 : k + 3 + l].decode("utf-8", errors="ignore")
                        if name:
                            return name
                    k += 3 + l
            i += el
    except (IndexError, ValueError, UnicodeError):
        return None
    return None
