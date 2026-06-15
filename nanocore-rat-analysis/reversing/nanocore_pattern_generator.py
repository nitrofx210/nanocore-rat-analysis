"""
NanoCore RAT — Run Key Pattern Generator
=========================================
Reconstructs all 138 unique Registry Run key name + executable value combinations
from the three string arrays found in NanoCore RAT v1.2.2.0 source code via dnSpy.

Usage:
    python nanocore_pattern_generator.py
    # Outputs: nanocore_pattern.csv

Source:
    Orange CyberDefense CyberSOC Blog — "Malware Detection by Artifacts: The NanoCore Case"
    https://www.orangecyberdefense.com/global/blog/managed-detection-response/
    Values confirmed by dnSpy decompilation of Class8 in NanoCore Client.exe
"""

import csv
from pathlib import Path
from itertools import product

# ── String arrays extracted from NanoCore RAT v1.2.2.0 source (via dnSpy) ────
# Class8.string_2 — executable name suffixes (6 items)
string2 = ['ss', 'mon', 'mgr', 'sv', 'svc', 'host']

# Class8.string_3 — Run key display name suffixes (6 items)
string3 = ['Subsystem', 'Monitor', 'Manager', 'Service', 'Service', 'Host']

# Class8.string_4 — Network protocol prefixes (23 items)
string4 = [
    'dhcp', 'upnp', 'tcp',  'udp',  'saas', 'iss',  'smtp',
    'dos',  'dpi',  'pci',  'scsi', 'wan',  'lan',  'nat',
    'imap', 'nas',  'ntfs', 'wpa',  'dsl',  'agp',  'arp',
    'ddp',  'dns'
]


def generate_patterns(output_path: str = 'nanocore_pattern.csv') -> list:
    """
    Generate all 138 NanoCore Run key name / executable value combinations.

    Key name format:  string_4[i].upper() + ' ' + string_3[i]
                      e.g. 'TCP Monitor', 'NAS Host'

    Exe value format: string_4[i] + string_2[i] + '.exe'
                      e.g. 'tcpmon.exe', 'nashost.exe'

    The machine GUID is used as an index seed to select one pair.
    Confirmed pairs observed in sandboxes:
        - 'TCP Monitor' → tcpmon.exe  (sandbox A)
        - 'NAS Host'    → nashost.exe (sandbox B / OCD lab)
    """
    assert len(string2) == len(string3), "string2 and string3 must have equal length"

    patterns = []
    for s4 in string4:
        for s3, s2 in zip(string3, string2):
            key_name  = s4.upper() + ' ' + s3          # e.g. "TCP Monitor"
            exe_value = '*\\' + s4 + s2 + '.exe'        # e.g. "*\tcpmon.exe"
            patterns.append({
                'RUN Key Name': key_name,
                'Value':        exe_value,
                'Description':  'Nanocore-RAT',
                'string4':      s4,
                'string3':      s3,
                'string2':      s2,
            })

    print(f'Generated {len(patterns)} NanoCore pattern combinations')
    print(f'  string4 × (string3,string2) = {len(string4)} × {len(string3)} = {len(patterns)}')

    # Write CSV
    out = Path(output_path)
    with open(out, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['RUN Key Name', 'Value', 'Description'])
        writer.writeheader()
        for p in patterns:
            writer.writerow({k: p[k] for k in ['RUN Key Name', 'Value', 'Description']})

    print(f'\nSaved → {out.resolve()}')
    print('\nSample patterns (first 8):')
    print(f'{"Run Key Name":<22} {"Value":<20} {"Description"}')
    print('-' * 58)
    for p in patterns[:8]:
        print(f'{p["RUN Key Name"]:<22} {p["Value"]:<20} {p["Description"]}')

    # Confirm known sandbox observations
    print('\nConfirmed sandbox observations:')
    known = [
        ('TCP Monitor', '*\\tcpmon.exe'),
        ('NAS Host',    '*\\nashost.exe'),
    ]
    for kn, kv in known:
        match = next((p for p in patterns if p['RUN Key Name'] == kn and p['Value'] == kv), None)
        if match:
            print(f'  ✓  {kn} → {kv}')
        else:
            print(f'  ✗  NOT FOUND: {kn} → {kv}')

    return patterns


def generate_siem_lookuptable(patterns: list, output_path: str = 'nanocore_siem_lookup.csv'):
    """
    Generate a Splunk-compatible lookup table CSV for registry artifact detection.
    Use with: | lookup nanocore_siem_lookup key_name AS registry_value_name OUTPUT malware_family
    """
    out = Path(output_path)
    with open(out, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['key_name', 'exe_value', 'malware_family', 'confidence'])
        for p in patterns:
            clean_val = p['Value'].replace('*\\', '')   # strip wildcard prefix
            writer.writerow([p['RUN Key Name'], clean_val, 'NanoCore-RAT', 'HIGH'])
    print(f'SIEM lookup table saved → {out.resolve()} ({len(patterns)} rows)')


if __name__ == '__main__':
    patterns = generate_patterns('nanocore_pattern.csv')
    generate_siem_lookuptable(patterns, 'nanocore_siem_lookup.csv')

    print('\n' + '='*60)
    print('STATISTICS')
    print('='*60)
    print(f'  Total combinations:  {len(patterns)}')
    print(f'  string4 prefixes:    {len(string4)}  ({", ".join(string4)})')
    print(f'  string3 suffixes:    {len(string3)}  ({", ".join(string3)})')
    print(f'  string2 exe stems:   {len(string2)}  ({", ".join(string2)})')
    print()
    print('MITRE ATT&CK:')
    print('  T1547.001 — Boot or Logon Autostart: Registry Run Keys')
    print('  T1053.005 — Scheduled Task/Job (same string_4[i] as /tn value)')
