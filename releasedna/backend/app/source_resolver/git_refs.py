"""Bounded public Git ref discovery; no git process, checkout, hooks or credentials."""
import re

from app.core.safety import InspectionError


def advertised_tags(fetcher, slug, candidates):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', slug):
        raise InspectionError('Invalid GitHub repository slug')
    data = fetcher.get(f'https://github.com/{slug}.git/info/refs?service=git-upload-pack', limit=8 * 1024 * 1024)
    packets, pos = [], 0
    while pos < len(data):
        prefix = data[pos:pos + 4]
        if not re.fullmatch(b'[0-9a-fA-F]{4}', prefix):
            raise InspectionError('Invalid Git ref packet length')
        size = int(prefix, 16)
        if size == 0:
            packets.append(None)
            pos += 4
            continue
        if size < 4 or size > 65520 or pos + size > len(data):
            raise InspectionError('Truncated or oversized Git ref packet')
        packets.append(data[pos + 4:pos + size])
        pos += size
    if len(packets) < 3 or packets[:2] != [b'# service=git-upload-pack\n', None] or packets[-1] is not None:
        raise InspectionError('Incomplete Git ref advertisement')
    refs = {}
    for packet in packets[2:-1]:
        if packet is None:
            raise InspectionError('Unexpected Git ref flush')
        line = packet.split(b'\0', 1)[0].rstrip(b'\n')
        match = re.fullmatch(rb'([0-9a-f]{40}) ([^\s\x00]+)', line)
        if not match:
            raise InspectionError('Malformed Git ref advertisement')
        sha, ref = match.groups()
        if ref in refs:
            raise InspectionError('Duplicate Git ref advertisement')
        refs[ref] = sha.decode('ascii')
    result = {}
    for tag in candidates:
        ref = ('refs/tags/' + tag).encode('utf-8')
        if ref in refs:
            result[tag] = refs.get(ref + b'^{}', refs[ref])
    return result
