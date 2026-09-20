#!/usr/bin/env python3
"""
BloodHound ZIP Analyzer v2 - Fixed for actual SharpHound JSON schema
Handles both old (nodes/relationships) and new ({"data": [...], "meta": {...}}) formats.
"""

import zipfile
import json
import sys
import re
from collections import defaultdict
from pathlib import Path


class BloodhoundAnalyzer:
    def __init__(self, zip_path):
        self.zip_path = zip_path
        self.objects = []          # all entity dicts, flattened
        self.relationships = []    # all ACL/edge dicts
        self.by_name = {}
        self.by_sid = {}
        self.vulnerabilities = []
        self.file_types = {}       # filename -> meta.type

    # ---------- LOADING ----------

    def load_zip(self):
        try:
            with zipfile.ZipFile(self.zip_path, 'r') as zf:
                names = zf.namelist()
                json_files = [n for n in names if n.lower().endswith('.json')]
                print(f"[*] ZIP contains {len(names)} files, {len(json_files)} JSON files:")
                for n in json_files:
                    print(f"      - {n}")

                if not json_files:
                    print("[-] No JSON files found in ZIP")
                    return False

                parsed = 0
                for jf in json_files:
                    try:
                        raw = zf.read(jf).decode('utf-8-sig', errors='replace').strip()
                        if not raw:
                            continue
                        data = json.loads(raw)
                    except (json.JSONDecodeError, UnicodeDecodeError) as e:
                        print(f"[!] Could not parse {jf}: {e}")
                        continue
                    parsed += self._ingest(data, jf)

                if parsed == 0:
                    print("[-] ZIP parsed but zero entities extracted - unknown schema?")
                    return False

                self.by_name = {o['name'].upper(): o for o in self.objects if o.get('name')}
                self.by_sid = {o['sid']: o for o in self.objects if o.get('sid')}
                print(f"\n[+] Extracted {len(self.objects)} entities and {len(self.relationships)} edges/ACLs")
                print(f"[+] Entity type breakdown:")
                for t, c in sorted(self._type_counts().items()):
                    print(f"      {t:<15} {c}")
                return True
        except zipfile.BadZipFile:
            print(f"[-] {self.zip_path} is not a valid ZIP file")
            return False

    def _type_counts(self):
        counts = defaultdict(int)
        for o in self.objects:
            counts[o['type']] += 1
        return counts

    def _ingest(self, data, filename):
        """Handle both SharpHound format and legacy graph format."""
        count = 0

        # ----- Modern SharpHound format: {"data": [...], "meta": {"type": "user" ...}}
        if isinstance(data, dict) and 'data' in data and isinstance(data['data'], list):
            meta = data.get('meta', {})
            file_type = meta.get('type', 'unknown').lower()
            self.file_types[filename] = file_type

            for item in data['data']:
                if not isinstance(item, dict):
                    continue
                if 'ObjectIdentifier' in item or 'Properties' in item:
                    count += self._add_sharphound_entity(item, file_type)
                elif 'RightName' in item or 'IsACL' in item or 'RelationType' in item:
                    # ACL / edge entry
                    self.relationships.append(self._normalize_edge(item, filename))
                    count += 1

        # ----- Legacy / raw graph format: {"nodes": [...], "relationships": [...]}
        elif isinstance(data, dict):
            for node in data.get('nodes', []) or []:
                count += self._add_sharphound_entity(node, 'unknown')
            for rel in data.get('relationships', []) or []:
                self.relationships.append(self._normalize_edge(rel, filename))
                count += 1

        # ----- Bare list of entities
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and ('ObjectIdentifier' in item or 'Properties' in item):
                    count += self._add_sharphound_entity(item, 'unknown')

        return count

    def _add_sharphound_entity(self, item, file_type):
        props = item.get('Properties', {}) or {}
        aces = item.get('Aces', []) or []

        # Determine type
        etype = (file_type or 'unknown').lower()
        if etype in ('unknown', ''):
            if item.get('AllowedToDelegate') is not None:
                etype = 'user'
            sid = item.get('ObjectIdentifier', '')
            if re.match(r'^S-1-5-21-.*-512$', sid):
                etype = 'group'
            elif sid.endswith('-502'):
                etype = 'user'

        name = props.get('name') or item.get('Label') or item.get('name') or 'UNKNOWN'
        obj = {
            'type': etype,
            'name': name,
            'sid': item.get('ObjectIdentifier', props.get('objectid', '')),
            'props': props,
            'aces': aces,
            'delegation': item.get('AllowedToDelegate', []),
            'raw': {k: v for k, v in item.items() if k not in ('Properties', 'Aces', 'raw')},
        }
        self.objects.append(obj)

        # Index ACEs as edges too
        for ace in aces:
            self.relationships.append({
                'src_sid': ace.get('PrincipalSID'),
                'src_name': ace.get('PrincipalName', ace.get('PrincipalSID')),
                'right': ace.get('RightName'),
                'ace_type': ace.get('AceType'),
                'target_sid': obj['sid'],
                'target_name': name,
                'file': 'inline_aces',
            })
        return 1

    def _normalize_edge(self, rel, filename):
        return {
            'src_sid': rel.get('SourceObjectSid') or rel.get('src') or rel.get('startNode'),
            'tgt_sid': rel.get('TargetObjectSid') or rel.get('tgt') or rel.get('endNode'),
            'right': rel.get('RightName') or rel.get('type'),
            'ace_type': rel.get('AceType'),
            'src_name': rel.get('PrincipalName', rel.get('src_name', '')),
            'target_name': rel.get('TargetName', ''),
            'file': filename,
        }

    # ---------- ANALYSIS ----------

    def find_krbtgt(self):
        print("\n" + "=" * 60)
        print("GOLDEN TICKET ANALYSIS (KRBTGT)")
        print("=" * 60)
        found = False
        for o in self.objects:
            name = o['name'].upper()
            if 'KRBTGT' in name and o['type'] == 'user':
                found = True
                p = o['props']
                print(f"\n[!] KRBTGT account: {o['name']}")
                print(f"      SID: {o['sid']}")
                print(f"      Enabled: {p.get('enabled', 'N/A')}")
                print(f"      Password Last Set: {p.get('pwdlastset', 'N/A')}")
                print(f"      Notes: hash NOT in BloodHound data - must be dumped")
                print(f"             via DCSync (secretsdump.py) or Mimikatz lsadump::dcsync")
                self.vulnerabilities.append({
                    'type': 'GOLDEN_TICKET_TARGET', 'severity': 'CRITICAL',
                    'target': o['name'],
                    'details': 'KRBTGT present; obtain hash via DCSync to forge Golden Tickets'
                })
        if not found:
            print("[+] No KRBTGT user found in export (check if user collection was run)")
        return found

    def find_kerberoasting(self):
        print("\n" + "=" * 60)
        print("KERBEROASTING ANALYSIS (SPN-bearing accounts)")
        print("=" * 60)
        targets = []
        for o in self.objects:
            if o['type'] not in ('user', 'unknown'):
                continue
            p = o['props']
            spns = p.get('serviceprincipalnames', p.get('spn', []))
            if isinstance(spns, str):
                spns = [spns]
            if not spns:
                continue
            # skip domain controllers (SPNs on DCs are normal)
            if 'isdc' in p and p['isdc']:
                continue
            name = o['name']
            if name.upper().startswith('KRBTGT'):
                continue
            targets.append((o, spns))

        if targets:
            print(f"\n[!] {len(targets)} Kerberoastable account(s):")
            print("-" * 80)
            for o, spns in sorted(targets, key=lambda x: x[0]['name']):
                p = o['props']
                admin_flag = p.get('admincount', False)
                flag = " [ADMINCOUNT]" if admin_flag else ""
                print(f"  {o['name']:<35} SPNs: {', '.join(spns[:3])}{flag}")
                self.vulnerabilities.append({
                    'type': 'KERBEROASTING', 'severity': 'HIGH' if admin_flag else 'MEDIUM',
                    'target': o['name'], 'spn': spns,
                    'details': f"SPN-bearing account{' with adminCount=1' if admin_flag else ''}"
                })
            print("\n[*] Attack: impacket-GetUserSPNs <domain>/<user>:<pass> -request")
            print("    Crack:  hashcat -m 13100 hashes.txt wordlist.txt")
        else:
            print("[+] No Kerberoastable accounts found")
        return targets

    def find_asrep_roasting(self):
        print("\n" + "=" * 60)
        print("AS-REP ROASTING ANALYSIS (DONT_REQ_PREAUTH)")
        print("=" * 60)
        targets = []
        for o in self.objects:
            p = o['props']
            # SharpHound stores this flag various ways
            no_preauth = (p.get('dontreqpreauth') is True or
                          p.get('dontreqpreauth') == 1 or
                          (isinstance(p.get('useraccountcontrol'), int) and
                           p['useraccountcontrol'] & 0x400000))
            if no_preauth:
                targets.append(o)
                print(f"[!] AS-REP roastable: {o['name']} (DONT_REQ_PREAUTH set)")
                self.vulnerabilities.append({
                    'type': 'ASREP_ROASTING', 'severity': 'HIGH',
                    'target': o['name'],
                    'details': 'Account does not require Kerberos pre-authentication'
                })
        if targets:
            print("\n[*] Attack: impacket-GetNPUsers <domain>/ -usersfile users.txt -no-pass")
            print("    Crack:  hashcat -m 18200 hashes.txt wordlist.txt")
        else:
            print("[+] No AS-REP roastable accounts found")
        return targets

    def find_delegation(self):
        print("\n" + "=" * 60)
        print("DELEGATION ABUSE ANALYSIS")
        print("=" * 60)
        found = 0
        for o in self.objects:
            p = o['props']
            uac = p.get('useraccountcontrol', 0)
            if isinstance(uac, int) and (uac & 0x100000):  # TRUSTED_FOR_DELEGATION
                found += 1
                print(f"[!] UNCONSTRAINED DELEGATION: {o['name']} ({o['type']})")
                if p.get('isdc'):
                    print("      (normal for Domain Controllers)")
                else:
                    self.vulnerabilities.append({
                        'type': 'UNCONSTRAINED_DELEGATION', 'severity': 'HIGH',
                        'target': o['name'],
                        'details': 'TRUSTED_FOR_DELEGATION - capture TGTs, e.g. via print spooler coercion'
                    })
            # Resource-based / constrained: AllowedToDelegate array
            if o.get('delegation'):
                found += 1
                print(f"[!] CONSTRAINED/RBCD targets: {o['name']} -> {o['delegation']}")
                self.vulnerabilities.append({
                    'type': 'CONSTRAINED_DELEGATION', 'severity': 'HIGH',
                    'target': o['name'],
                    'details': f"AllowedToDelegate: {o['delegation']}"
                })
            if isinstance(uac, int) and (uac & 0x4000000) and (uac & 0x1000000):
                # TRUSTED_TO_AUTH_FOR_DELEGATION + TRUSTED_FOR_DELEGATION = protocol transition
                print(f"[!] PROTOCOL TRANSITION enabled: {o['name']}")
        if not found:
            print("[+] No delegation misconfigurations found")
        if found:
            print("\n[*] RBCD attack: impacket-rbcd or PowerView SetDomainObjectAttributes")

    def find_dc_sync_and_aces(self):
        print("\n" + "=" * 60)
        print("DCSYNC / PRIVILEGED ACL ANALYSIS")
        print("=" * 60)
        dcsync_rights = {'DS-Replication-Get-Changes', 'DS-Replication-Get-Changes-All',
                         'GetChanges', 'GetChangesAll', 'AllExtendedRights'}
        generic_rights = {'GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner',
                          'Owns', 'ForceChangePassword', 'AllExtendedRights'}
        count = 0
        for rel in self.relationships:
            right = (rel.get('right') or '')
            if not right:
                continue
            src = rel.get('src_name') or rel.get('src_sid') or '?'
            tgt = rel.get('target_name') or rel.get('tgt_sid') or '?'
            if right in dcsync_rights:
                count += 1
                print(f"[!] DCSYNC RIGHT: {src} -> {tgt} ({right})")
                self.vulnerabilities.append({
                    'type': 'DCSYNC', 'severity': 'CRITICAL',
                    'target': f"{src} -> {tgt}",
                    'details': f'{right} - can dump all hashes incl. KRBTGT (Golden Ticket!)'
                })
            elif right in generic_rights:
                count += 1
                sev = 'HIGH' if right in ('GenericAll', 'GenericWrite', 'Owns') else 'MEDIUM'
                print(f"[!] ABUSABLE ACL: {src} -> {tgt} ({right})")
                self.vulnerabilities.append({
                    'type': 'ACL_ABUSE', 'severity': sev,
                    'target': f"{src} -> {tgt}", 'details': right
                })
        if not count:
            print("[+] No privileged ACEs/edges found (ACL collection may be missing)")
        else:
            print("\n[*] DCSync: secretsdump.py <domain>/<user>:<pass>@<dc_ip>")

    def find_admin_members(self):
        print("\n" + "=" * 60)
        print("PRIVILEGED ACCOUNT ANALYSIS")
        print("=" * 60)
        high_value = [o for o in self.objects if o['props'].get('highvalue')]
        admincount = [o for o in self.objects
                      if o['type'] == 'user' and o['props'].get('admincount')]
        if high_value:
            print(f"[!] High-value targets flagged by BloodHound: {len(high_value)}")
            for o in high_value:
                print(f"      - {o['name']} ({o['type']})")
                self.vulnerabilities.append({
                    'type': 'HIGH_VALUE', 'severity': 'HIGH',
                    'target': o['name'], 'details': 'BloodHound high-value target'
                })
        if admincount:
            print(f"[+] adminCount=1 users: {', '.join(o['name'] for o in admincount[:15])}"
                  + (' ...' if len(admincount) > 15 else ''))
            self.vulnerabilities.append({
                'type': 'PRIVILEGED_MEMBER', 'severity': 'MEDIUM',
                'target': ', '.join(o['name'] for o in admincount),
                'details': f'{len(admincount)} users with adminCount=1'
            })
        if not high_value and not admincount:
            print("[+] No high-value or admin-flagged accounts found")

    def find_password_issues(self):
        print("\n" + "=" * 60)
        print("PASSWORD / ACCOUNT HYGIENE")
        print("=" * 60)
        for o in self.objects:
            if o['type'] != 'user':
                continue
            p = o['props']
            name = o['name']
            if p.get('enabled') is False:
                continue
            if p.get('dontexpirepassword') is True:
                print(f"[!] Password never expires: {name}")
                self.vulnerabilities.append({
                    'type': 'PASSWORD_NEVER_EXPIRES', 'severity': 'LOW',
                    'target': name, 'details': 'Stale credential risk'
                })
            if p.get('passwordnotreqd') is True or p.get('passwornotrequired') is True:
                print(f"[!] PASSWORD NOT REQUIRED: {name}")
                self.vulnerabilities.append({
                    'type': 'PASSWORD_NOT_REQUIRED', 'severity': 'MEDIUM',
                    'target': name, 'details': 'Account may have blank password'
                })
            if p.get('sensitive') is False and p.get('admincount'):
                print(f"[!] Admin account NOT marked sensitive (forwardable TGT risk): {name}")

    # ---------- REPORT ----------

    def save_report(self, out='bloodhound_report.json'):
        sev = lambda s: len([v for v in self.vulnerabilities if v['severity'] == s])
        report = {
            'source': str(Path(self.zip_path).name),
            'entities_parsed': len(self.objects),
            'edges_parsed': len(self.relationships),
            'total_findings': len(self.vulnerabilities),
            'summary': {k: sev(k) for k in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')},
            'findings': self.vulnerabilities,
        }
        with open(out, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] Report saved to {out}")

    def run(self):
        if not self.load_zip():
            sys.exit(1)
        self.find_krbtgt()
        self.find_kerberoasting()
        self.find_asrep_roasting()
        self.find_delegation()
        self.find_dc_sync_and_aces()
        self.find_admin_members()
        self.find_password_issues()

        print("\n" + "=" * 60)
        print("SUMMARY")
        print("=" * 60)
        sev = lambda s: len([v for v in self.vulnerabilities if v['severity'] == s])
        print(f"Entities: {len(self.objects)} | Edges/ACLs: {len(self.relationships)}")
        print(f"Findings: {len(self.vulnerabilities)} "
              f"(CRITICAL: {sev('CRITICAL')}, HIGH: {sev('HIGH')}, "
              f"MEDIUM: {sev('MEDIUM')}, LOW: {sev('LOW')})")
        self.save_report()


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python bh_analyzer_v2.py <bloodhound_export.zip>")
        sys.exit(1)
    BloodhoundAnalyzer(sys.argv[1]).run()
