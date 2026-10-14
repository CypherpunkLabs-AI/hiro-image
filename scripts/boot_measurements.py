"""Calculate the GPT and UKI event digests from the actual disk bytes.

GPT hashing follows EFI_GPT_DATA in EDK2 DxeTpm2MeasureBootLib. PE hashing
follows the UEFI/Authenticode algorithm (not a hash of the entire file).
The platform module combines these image-derived digests with qualified
firmware events to calculate expected RTMR values.
"""
import hashlib
import re
import struct
import subprocess
import tempfile
import uuid
import zlib
from pathlib import Path

from image_lib import require

ZERO = bytes(48)
ESP = uuid.UUID('c12a7328-f81f-11d2-ba4b-00a0c93ec93b').bytes_le


def sha384(data):
    return hashlib.sha384(data).hexdigest()


def hex_digest(value, size=48):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{' + str(size * 2) + '}', value),
            f'expected a {size}-byte lowercase hex digest')
    return bytes.fromhex(value)


def extend(events):
    register = ZERO
    for event in events:
        register = hashlib.sha384(register + hex_digest(event['sha384'])).digest()
    return register.hex()


def read_exact(stream, offset, size):
    stream.seek(offset)
    data = stream.read(size)
    require(len(data) == size, 'truncated disk data')
    return data


def measure_gpt(disk, sector=512):
    """Validate both GPT copies; measure the primary header and populated entries."""
    size = disk.stat().st_size
    require(sector in (512, 4096) and size % sector == 0, 'invalid disk sector alignment')
    last_lba = size // sector - 1
    with disk.open('rb') as stream:
        mbr = read_exact(stream, 0, 512)
        require(mbr[510:] == b'\x55\xaa' and mbr[450] == 0xee, 'missing protective MBR')

        def table(lba, other):
            header = read_exact(stream, lba * sector, 92)
            require(header[:8] == b'EFI PART', 'missing GPT signature')
            revision, length, crc, reserved = struct.unpack_from('<IIII', header, 8)
            require(revision == 0x10000 and length == 92 and reserved == 0,
                    'unsupported GPT header format')
            cleared = header[:16] + bytes(4) + header[20:]
            require(zlib.crc32(cleared) == crc, 'GPT header CRC mismatch')
            current, backup, first, last = struct.unpack_from('<QQQQ', header, 24)
            require((current, backup) == (lba, other), 'GPT backup not at final disk boundary')
            array_lba, count, width, array_crc = struct.unpack_from('<QIII', header, 72)
            require(1 <= count <= 4096 and width == 128, 'unsupported GPT entry layout')
            require(2 <= first <= last < last_lba, 'invalid GPT usable range')
            array_end = array_lba + (count * width + sector - 1) // sector
            require((lba == 1 and 2 <= array_lba < array_end <= first) or
                    (lba == last_lba and last < array_lba < array_end <= last_lba),
                    'GPT array overlaps usable space')
            entries = read_exact(stream, array_lba * sector, count * width)
            require(zlib.crc32(entries) == array_crc, 'GPT partition array CRC mismatch')
            return header, entries, first, last

        header, entries, first, last = table(1, last_lba)
        backup, backup_entries, backup_first, backup_last = table(last_lba, 1)
        require(header[56:72] == backup[56:72] and entries == backup_entries
                and (first, last) == (backup_first, backup_last), 'GPT copies disagree')
    populated = [entries[i:i + 128] for i in range(0, len(entries), 128)
                 if entries[i:i + 16] != bytes(16)]
    ranges, esps = [], []
    for entry in populated:
        start, end = struct.unpack_from('<QQ', entry, 32)
        require(first <= start <= end <= last, 'partition outside GPT usable space')
        ranges.append((start, end))
        if entry[:16] == ESP:
            esps.append((start, end))
    ranges.sort()
    require(all(a[1] < b[0] for a, b in zip(ranges, ranges[1:])), 'overlapping partitions')
    require(len(esps) == 1, 'expected exactly one EFI system partition')
    event = header + struct.pack('<Q', len(populated)) + b''.join(populated)
    return {'sha384': sha384(event), 'event_bytes': len(event),
            'disk_guid': str(uuid.UUID(bytes_le=header[56:72])), 'sector_size': sector,
            'partition_count': len(populated), 'esp_start_lba': esps[0][0],
            'esp_size_lba': esps[0][1] - esps[0][0] + 1}


def measure_pe(data):
    """SHA-384 Authenticode digest plus the UKI's required embedded sections."""
    require(len(data) >= 64 and data[:2] == b'MZ', 'UKI is not a DOS/PE image')
    pe = struct.unpack_from('<I', data, 60)[0]
    require(64 <= pe <= len(data) - 24 and data[pe:pe + 4] == b'PE\0\0', 'invalid PE header')
    machine, count = struct.unpack_from('<HH', data, pe + 4)
    optional_size = struct.unpack_from('<H', data, pe + 20)[0]
    optional = pe + 24
    require(machine == 0x8664 and 1 <= count <= 96 and optional_size >= 152
            and optional + optional_size + count * 40 <= len(data), 'unsupported PE layout')
    require(struct.unpack_from('<H', data, optional)[0] == 0x20b, 'expected PE32+ UKI')
    require(struct.unpack_from('<H', data, optional + 68)[0] == 10, 'expected EFI application')
    headers = struct.unpack_from('<I', data, optional + 60)[0]
    directories = struct.unpack_from('<I', data, optional + 108)[0]
    require(5 <= directories <= (optional_size - 112) // 8, 'invalid PE data directories')
    require(optional + optional_size + count * 40 <= headers <= len(data), 'invalid PE header size')
    checksum = optional + 64
    security = optional + 112 + 4 * 8
    cert_offset, cert_size = struct.unpack_from('<II', data, security)
    require((cert_offset == cert_size == 0) or
            (cert_offset % 8 == 0 and cert_size >= 8 and cert_offset + cert_size == len(data)),
            'certificate table must be at end of PE file')
    h = hashlib.sha384()
    h.update(data[:checksum])
    h.update(data[checksum + 4:security])
    h.update(data[security + 8:headers])
    sections = []
    required = {}
    for i in range(count):
        position = optional + optional_size + i * 40
        name = bytes(data[position:position + 8]).rstrip(b'\0')
        virtual_size = struct.unpack_from('<I', data, position + 8)[0]
        raw_size, offset = struct.unpack_from('<II', data, position + 16)
        if raw_size:
            require(headers <= offset and offset + raw_size <= len(data) - cert_size,
                    'PE section outside file')
            sections.append((offset, raw_size))
        if name in (b'.linux', b'.osrel', b'.cmdline', b'.initrd', b'.uname', b'.sbat'):
            require(name.decode() not in required and 0 < virtual_size <= raw_size, 'invalid embedded UKI section')
            required[name.decode()] = data[offset:offset + virtual_size]
        # These change the measured boot sequence; qualify a new profile before
        # allowing them instead of silently omitting their measurements.
        require(name not in (b'.ucode', b'.splash', b'.dtb', b'.dtbauto', b'.hwids',
                             b'.pcrpkey', b'.profile', b'.efifw', b'.pcrsig'),
                'UKI section requires a new boot profile: ' + repr(name))
    require({'.linux', '.initrd', '.cmdline'} <= set(required), 'missing UKI kernel, initrd or command line')
    end = headers
    summed = headers
    for offset, raw_size in sorted(sections):
        require(offset >= end, 'overlapping PE sections')
        h.update(data[offset:offset + raw_size])
        end = offset + raw_size
        summed += raw_size
    # Authenticode hashes trailing data using SumOfBytesHashed, excluding the
    # certificate directory and certificate table. Checksum also stays excluded.
    require(summed <= len(data) - cert_size, 'invalid PE section byte count')
    h.update(data[summed:len(data) - cert_size])
    return h.hexdigest(), required
