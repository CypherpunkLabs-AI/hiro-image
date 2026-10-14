"""Shared build helpers; no application release or provider policy inputs."""
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
ESP = 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b'
ROOT_PARTITION = '4f68bce3-e8cd-4db1-96e7-fbcaf984b709'
VERITY = '2c7357ed-ebd2-46d9-aec1-23d437ec2bf5'
TOOL_PATHS = ('flake.nix', 'flake.lock', 'VERSION', 'LICENSE',
              'scripts/image_lib.py', 'scripts/boot_measurements.py',
              'scripts/platform_measurements.py',
              'scripts/select-os', 'scripts/assemble-release', 'scripts/collect-evidence')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_release_inputs():
    missing = [name for name in TOOL_PATHS
               if not (ROOT / name).is_file()]
    require(not missing, 'missing release input files: ' + ', '.join(missing))


def run(*args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, **kwargs)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def version():
    value = (ROOT / 'VERSION').read_text().strip()
    require(re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?', value),
            'VERSION must be a release version such as 0.1.0 or 0.1.0-rc.1')
    return value


def partitions(disk):
    table = json.loads(subprocess.check_output(['sfdisk', '--json', str(disk)]))['partitiontable']
    require(table['label'] == 'gpt' and table['sectorsize'] == 512, 'expected 512-byte sector GPT disk')
    result = {}
    for kind in (ESP, ROOT_PARTITION, VERITY):
        matches = [p for p in table['partitions'] if p['type'].lower() == kind]
        require(len(matches) == 1, 'missing or duplicate partition ' + kind)
        result[kind] = matches[0]
    require(len(table['partitions']) == 3, 'unexpected additional partition')
    return result


def copy_partition(disk, part, output):
    run('dd', 'if=' + str(disk), 'of=' + str(output), 'bs=512',
        'skip=' + str(part['start']), 'count=' + str(part['size']), 'status=none')


def finalize_disk(disk):
    """Fix the GCP disk size/GPT before boot verification and measurement."""
    gib = 1024 ** 3
    with Path(disk).open('ab') as stream:
        stream.truncate(((Path(disk).stat().st_size + gib - 1) // gib) * gib)
    run('sgdisk', '--move-second-header', disk)


def archive_disk(disk, output):
    with Path(output).open('wb') as dest:
        tar = subprocess.Popen(['tar', '--format=oldgnu', '--sparse', '--mtime=@0', '--owner=0', '--group=0',
                                '--numeric-owner', '--transform=s/.*/disk.raw/', '-C', str(disk.parent),
                                '-c', disk.name], stdout=subprocess.PIPE)
        try:
            gzip = subprocess.run(['gzip', '-n'], stdin=tar.stdout, stdout=dest)
        finally:
            tar.stdout.close()
        require(tar.wait() == 0 and gzip.returncode == 0, 'disk archive failed')


def checksums(directory):
    directory = Path(directory)
    (directory / 'SHA256SUMS').write_text(''.join(
        f'{digest(p)}  {p.name}\n' for p in sorted(directory.iterdir())
        if p.is_file() and p.name != 'SHA256SUMS'))
