#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path
import sys


def load_capture(path):
    data = Path(path).read_bytes()
    if data.lstrip().startswith(b"{"):
        document = json.loads(data)
        raw_hex = document.get("raw_hex")
        if not raw_hex:
            raise ValueError(f"{path}: JSON does not contain raw_hex")
        return bytes.fromhex(raw_hex)
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return data
    compact = "".join(text.split())
    if compact and len(compact) % 2 == 0 and all(character in "0123456789abcdefABCDEF" for character in compact):
        return bytes.fromhex(compact)
    return data


def read_u16(data, offset, end):
    if offset + 2 > end:
        raise ValueError("truncated uint16")
    return int.from_bytes(data[offset:offset + 2], "big"), offset + 2


def read_vector_u16(data, offset, end):
    length, offset = read_u16(data, offset, end)
    vector_end = offset + length
    if vector_end > end:
        raise ValueError("truncated uint16 vector")
    values = []
    while offset < vector_end:
        value, offset = read_u16(data, offset, vector_end)
        values.append(value)
    return values, vector_end


def is_grease(value):
    return value & 0x0F0F == 0x0A0A


def without_grease(values):
    return [value for value in values if not is_grease(value)]


def parse_extensions(data, start, end):
    extension_types = []
    extensions = {}
    offset = start
    while offset < end:
        extension_type, offset = read_u16(data, offset, end)
        length, offset = read_u16(data, offset, end)
        body_end = offset + length
        if body_end > end:
            raise ValueError("truncated extension")
        extension_types.append(extension_type)
        extensions[extension_type] = (offset, body_end)
        offset = body_end
    return extension_types, extensions


def parse_key_share(data, start, end, normalized):
    vector_length, offset = read_u16(data, start, end)
    vector_end = offset + vector_length
    if vector_end > end:
        raise ValueError("truncated key_share extension")
    groups = []
    while offset < vector_end:
        group, offset = read_u16(data, offset, vector_end)
        key_length, offset = read_u16(data, offset, vector_end)
        key_end = offset + key_length
        if key_end > vector_end:
            raise ValueError("truncated key_share public key")
        groups.append(group)
        normalized[offset:key_end] = b"\x00" * key_length
        offset = key_end
    return groups


def parse_client_hello(raw):
    if len(raw) < 9 or raw[0] != 0x16:
        raise ValueError("not a TLS handshake record")
    record_length = int.from_bytes(raw[3:5], "big")
    record_end = 5 + record_length
    if record_end > len(raw):
        raise ValueError("truncated TLS record")
    if raw[5] != 1:
        raise ValueError("first handshake is not ClientHello")
    hello_length = int.from_bytes(raw[6:9], "big")
    hello_start = 9
    hello_end = hello_start + hello_length
    if hello_end > record_end:
        raise ValueError("truncated ClientHello")

    normalized = bytearray(raw[:record_end])
    offset = hello_start
    legacy_version, offset = read_u16(raw, offset, hello_end)
    random_start = offset
    random_end = random_start + 32
    if random_end > hello_end:
        raise ValueError("truncated ClientHello random")
    normalized[random_start:random_end] = b"\x00" * 32
    offset = random_end

    if offset >= hello_end:
        raise ValueError("missing session ID length")
    session_id_length = raw[offset]
    offset += 1
    session_id_end = offset + session_id_length
    if session_id_end > hello_end:
        raise ValueError("truncated session ID")
    normalized[offset:session_id_end] = b"\x00" * session_id_length
    offset = session_id_end

    ciphers, offset = read_vector_u16(raw, offset, hello_end)
    if offset >= hello_end:
        raise ValueError("missing compression methods")
    compression_length = raw[offset]
    offset += 1 + compression_length
    if offset + 2 > hello_end:
        raise ValueError("missing extensions length")
    extensions_length = int.from_bytes(raw[offset:offset + 2], "big")
    extensions_start = offset + 2
    extensions_end = extensions_start + extensions_length
    if extensions_end > hello_end:
        raise ValueError("truncated extensions")

    extension_types, extensions = parse_extensions(raw, extensions_start, extensions_end)
    key_share_groups = []
    if 51 in extensions:
        key_share_start, key_share_end = extensions[51]
        key_share_groups = parse_key_share(raw, key_share_start, key_share_end, normalized)
    if 41 in extensions:
        psk_start, psk_end = extensions[41]
        normalized[psk_start:psk_end] = b"\x00" * (psk_end - psk_start)

    supported_groups = []
    if 10 in extensions:
        groups_start, groups_end = extensions[10]
        supported_groups, _ = read_vector_u16(raw, groups_start, groups_end)
    point_formats = []
    if 11 in extensions:
        points_start, points_end = extensions[11]
        if points_start >= points_end:
            raise ValueError("truncated point formats")
        point_length = raw[points_start]
        point_end = points_start + 1 + point_length
        if point_end > points_end:
            raise ValueError("truncated point formats")
        point_formats = list(raw[points_start + 1:point_end])

    ja3_values = [
        str(legacy_version),
        "-".join(str(value) for value in without_grease(ciphers)),
        "-".join(str(value) for value in without_grease(extension_types)),
        "-".join(str(value) for value in without_grease(supported_groups)),
        "-".join(str(value) for value in point_formats),
    ]
    ja3 = ",".join(ja3_values)
    return {
        "raw": raw[:record_end],
        "normalized": bytes(normalized),
        "ja3": ja3,
        "ja3_hash": hashlib.md5(ja3.encode("ascii")).hexdigest(),
        "record_length": record_end,
        "session_id_length": session_id_length,
        "extension_types": extension_types,
        "key_share_groups": key_share_groups,
    }


def print_capture(label, path, capture):
    print(f"{label}: {path}")
    print(f"  raw record bytes: {capture['record_length']}")
    print(f"  session ID length: {capture['session_id_length']}")
    print(f"  extensions: {'-'.join(str(value) for value in capture['extension_types'])}")
    print(f"  key_share groups: {'-'.join(str(value) for value in capture['key_share_groups']) or '(none)'}")
    print(f"  JA3: {capture['ja3']}")
    print(f"  JA3 hash: {capture['ja3_hash']}")


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: compare_claude_clienthello.py LEFT.json|bin RIGHT.json|bin")
    paths = sys.argv[1:]
    captures = []
    for path in paths:
        captures.append(parse_client_hello(load_capture(path)))

    print_capture("left", paths[0], captures[0])
    print_capture("right", paths[1], captures[1])
    print(f"JA3: {'MATCH' if captures[0]['ja3'] == captures[1]['ja3'] else 'DIFFERENT'}")
    if captures[0]["normalized"] == captures[1]["normalized"]:
        print("normalized ClientHello bytes: MATCH")
        return 0

    differences = [
        index
        for index, (left, right) in enumerate(zip(captures[0]["normalized"], captures[1]["normalized"]))
        if left != right
    ]
    length_difference = len(captures[0]["normalized"]) != len(captures[1]["normalized"])
    print("normalized ClientHello bytes: DIFFERENT")
    print(f"first differing offsets: {', '.join(str(index) for index in differences[:20]) or '(length only)'}")
    if length_difference:
        print("normalized record lengths differ")
    return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2)
