"""Expected boot measurements for the qualified GCP direct-UKI boot path.

This predicts measurements; it does not verify a live quote. The recipient
authenticates the release, verifies fresh hardware evidence, and compares it.
"""
import json
from pathlib import Path

from boot_measurements import ZERO, extend, hex_digest, sha384
from image_lib import digest, require

PROFILE = 'gcp-tdx-platform-profile.json'
SECTION_ORDER = ['.linux', '.osrel', '.cmdline', '.initrd', '.uname', '.sbat']


def load_profile(path, check_evidence=False):
    path = Path(path)
    profile = json.loads(path.read_text())
    require(profile.get('schema') == 1 and profile.get('kind') == 'h-image.gcp-tdx-platform.v1',
            'unsupported GCP platform profile')
    hex_digest(profile['mrtd'])
    require(profile['uki']['section_order'] == SECTION_ORDER, 'unqualified UKI measurement order')
    require(extend(profile['rtmr0_events']) == profile['rtmr0'], 'platform RTMR0 reference mismatch')
    if check_evidence:
        for name, expected in profile['evidence']['files'].items():
            require(Path(name).name == name and name not in ('.', '..'), 'invalid evidence filename')
            require(digest(path.parent / 'evidence' / name) == expected,
                    'qualification evidence changed: ' + name)
    return profile


def expected_boot(profile, gpt_hash, uki_hash, section_hashes):
    """Use actual image hashes, never the captured image's RTMR1/RTMR2."""
    hex_digest(gpt_hash)
    hex_digest(uki_hash)
    require(set(section_hashes) == set(SECTION_ORDER), 'UKI sections differ from the qualified boot path')

    def event(kind, description, value):
        hex_digest(value)
        return {'type': kind, 'description': description, 'sha384': value}

    def action(text):
        return event(0x80000007, text, sha384(text.encode('ascii')))

    rtmr1 = [action('Calling EFI Application from Boot Option'),
             event(4, 'separator', sha384(bytes(4))),
             event(0x80000006, 'GPT', gpt_hash),
             event(0x80000003, 'UKI Authenticode', uki_hash),
             action('Exit Boot Services Invocation'),
             action('Exit Boot Services Returned with Success')]
    rtmr2 = []
    for name in SECTION_ORDER:
        rtmr2.extend([event(13, name + ' name', sha384(name.encode('ascii') + b'\0')),
                      event(13, name + ' contents', section_hashes[name])])
    return {'mrtd': profile['mrtd'], 'rtmr0': extend(profile['rtmr0_events']),
            'rtmr1': extend(rtmr1), 'rtmr2': extend(rtmr2), 'rtmr3': ZERO.hex(),
            'rtmr1_events': rtmr1, 'rtmr2_events': rtmr2}


def appraisal(profile_path, gpt, uki_hash, sections, stub):
    profile = load_profile(profile_path)
    require(digest(stub) == profile['uki']['stub_sha256'],
            'systemd stub changed: qualify its measurement sequence before release')
    return {'status': 'included', 'profile': PROFILE,
            'profile_sha256': digest(profile_path), 'profile_id': profile['id'],
            'launch': profile['launch'], 'scope': profile['scope'],
            'quote_requirements': profile['quote_requirements'],
            'expected_boot': expected_boot(profile, gpt['sha384'], uki_hash,
                                           {name: sha384(data) for name, data in sections.items()}),
            'rtmr3_scope': 'Before application startup. Application RTMR3 extensions must be separately appraised.',
            'live_quote_verified': False}
