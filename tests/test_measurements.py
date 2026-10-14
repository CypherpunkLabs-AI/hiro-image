"""Regression against the DCAP-verified GCP capture, plus changed-image cases."""
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from boot_measurements import measure_pe, sha384
from platform_measurements import PROFILE, SECTION_ORDER, appraisal, expected_boot, load_profile


class MeasurementTests(unittest.TestCase):
    def setUp(self):
        self.path = ROOT / 'platform' / PROFILE
        self.profile = load_profile(self.path, check_evidence=True)
        evidence = self.path.parent / 'evidence'
        self.manifest = json.loads((evidence / 'os-release.json').read_text())
        self.quote = (evidence / 'quote.bin').read_bytes()
        # Read the actual CCEL bytes, independently of the saved replay result.
        ccel = (evidence / 'ccel.bin').read_bytes()
        offset = 32 + struct.unpack_from('<I', ccel, 28)[0]
        self.events = []
        while ccel[offset:offset + 4] != b'\xff' * 4:
            index, kind, count = struct.unpack_from('<III', ccel, offset)
            offset += 12
            self.assertEqual(count, 1)
            self.assertEqual(struct.unpack_from('<H', ccel, offset)[0], 12)
            hashed = ccel[offset + 2:offset + 50].hex()
            offset += 50
            size = struct.unpack_from('<I', ccel, offset)[0]
            offset += 4
            data = ccel[offset:offset + size]
            offset += size
            self.events.append((index, kind, hashed, data))
        self.assertEqual(ccel[offset:], b'\xff' * (len(ccel) - offset))
        # This regression tests register construction from captured digests.
        # Release builds instead hash the actual newly built UKI sections.
        self.sections = {}
        for position, (_, kind, hashed, data) in enumerate(e for e in self.events if e[0] == 3):
            name = data.decode('utf-16-le').rstrip('\0')
            self.assertEqual(kind, 13)
            if position % 2:
                self.sections[name] = hashed
            else:
                self.assertEqual(hashed, sha384(name.encode() + b'\0'))

    def prediction(self, **overrides):
        inputs = dict(profile=self.profile, gpt_hash=self.manifest['boot']['gpt_event']['sha384'],
                      uki_hash=self.manifest['boot']['uki_pe_coff_sha384'], section_hashes=self.sections)
        inputs.update(overrides)
        return expected_boot(**inputs)

    def test_reference_matches_all_four_verified_registers(self):
        result = self.prediction()
        self.assertEqual(result['mrtd'], self.quote[184:232].hex())
        for n in range(4):
            self.assertEqual(result['rtmr' + str(n)], self.quote[376 + 48*n:424 + 48*n].hex())
        self.assertEqual([(e['type'], e['sha384']) for e in self.profile['rtmr0_events']],
                         [(kind, hashed) for index, kind, hashed, _ in self.events if index == 1])
        self.assertEqual([(e['type'], e['sha384']) for e in result['rtmr1_events']],
                         [(kind, hashed) for index, kind, hashed, _ in self.events if index == 2])

    def test_application_uki_recalculates_both_image_registers(self):
        sections = dict(self.sections, **{'.cmdline': sha384(b'new workload binding\0')})
        changed = self.prediction(uki_hash=sha384(b'new UKI'), section_hashes=sections)
        old = self.prediction()
        self.assertEqual(old['rtmr0'], changed['rtmr0'])
        self.assertNotEqual(old['rtmr1'], changed['rtmr1'])
        self.assertNotEqual(old['rtmr2'], changed['rtmr2'])

    def test_changed_gpt_changes_rtmr1_only(self):
        old, changed = self.prediction(), self.prediction(gpt_hash=sha384(b'new GPT'))
        self.assertNotEqual(old['rtmr1'], changed['rtmr1'])
        self.assertEqual(old['rtmr2'], changed['rtmr2'])

    def test_missing_or_extra_sections_rejected(self):
        for sections in [dict(self.sections, **{'.ucode': sha384(b'x')}),
                         {k: v for k, v in self.sections.items() if k != '.sbat'}]:
            with self.assertRaisesRegex(ValueError, 'UKI sections differ'):
                self.prediction(section_hashes=sections)

    def test_changed_stub_requires_qualification(self):
        with tempfile.TemporaryDirectory() as tmp:
            stub = Path(tmp) / 'stub'
            stub.write_bytes(b'new stub')
            with self.assertRaisesRegex(ValueError, 'systemd stub changed'):
                appraisal(self.path, {}, '', {}, stub)

    def test_pe_uses_virtual_section_bytes_not_alignment_padding(self):
        # Minimal valid PE32+ EFI fixture with six payload sections. Its raw
        # padding is deliberately nonzero, to catch hashing raw alignment.
        data = bytearray(1024 + len(SECTION_ORDER) * 512)
        data[:2] = b'MZ'
        struct.pack_into('<I', data, 60, 64)
        data[64:68] = b'PE\0\0'
        struct.pack_into('<HH', data, 68, 0x8664, len(SECTION_ORDER))
        struct.pack_into('<H', data, 84, 240)
        struct.pack_into('<H', data, 88, 0x20b)
        struct.pack_into('<I', data, 148, 1024)
        struct.pack_into('<H', data, 156, 10)
        struct.pack_into('<I', data, 196, 16)
        expected = {}
        for n, name in enumerate(SECTION_ORDER):
            header, offset = 328 + n*40, 1024 + n*512
            content = (name + ' payload\0').encode()
            expected[name] = content
            data[header:header + len(name)] = name.encode()
            struct.pack_into('<I', data, header + 8, len(content))
            struct.pack_into('<II', data, header + 16, 512, offset)
            data[offset:offset+512] = content + b'Z' * (512-len(content))
        _, sections = measure_pe(data)
        self.assertEqual(sections, expected)
        result = self.prediction(section_hashes={k: sha384(v) for k, v in sections.items()})
        self.assertEqual(result['rtmr2_events'][1]['sha384'], sha384(expected['.linux']))
