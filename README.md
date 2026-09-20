## BloodHound ZIP Analyzer v2
Offline analyzer for BloodHound / SharpHound ZIP exports that identifies Kerberos attack opportunities and Active Directory misconfigurations — Golden Tickets, Kerberoasting, AS-REP Roasting, delegation abuse, DCSync paths, and more.

No dependencies beyond Python 3.6+ standard library.

Requirements
Python 3.6+
A BloodHound ZIP export (SharpHound collector output)
bash

## On Kali Linux, if needed:
sudo apt install python3
Usage
bash

python bh_analyzer_v2.py <bloodhound_export.zip>
The script reads the ZIP directly — no extraction required.

Example output:

[*] ZIP contains 12 files, 12 JSON files:
      - _bloodhound.example.local.json
      - 20260920123456_users.json
      - 20260920123456_computers.json
      ...
      
[+] Extracted 1432 entities and 8912 edges/ACLs

[+] Entity type breakdown:
      user            412
      computer        388
      group           401
      domain          1
      ...

      
# What It Detects

Check	Severity	Details
Golden Ticket target (KRBTGT)	CRITICAL	Identifies KRBTGT accounts; flags that the hash must be dumped via DCSync first \
DCSync rights	CRITICAL	DS-Replication-Get-Changes(-All) / AllExtendedRights grants — also yields KRBTGT hash access \
Kerberoasting	HIGH/MEDIUM	User accounts with SPNs; elevated severity when adminCount=1 \
AS-REP Roasting	HIGH	Accounts with DONT_REQ_PREAUTH \
Unconstrained delegation	HIGH	TRUSTED_FOR_DELEGATION (UAC 0x100000), excluding normal DC entries \
Constrained / RBCD	HIGH	AllowedToDelegate arrays and protocol-transition flags \
ACL abuse	HIGH/MEDIUM	GenericAll, GenericWrite, WriteDacl, WriteOwner, Owns, ForceChangePassword
High-value targets	HIGH	Entities BloodHound itself flags as high-value \
Privileged accounts	MEDIUM	adminCount=1 users \
Password hygiene	LOW/MEDIUM	Password never expires, blank-password-allowed accounts, non-sensitive admins \
Each finding includes ready-to-run attack commands where applicable (Impacket, Rubeus, hashcat cracking modes). \

Output
Console report plus a machine-readable JSON file:

bash

bloodhound_report.json

json
{
  "source": "bloodhound_export.zip",
  "entities_parsed": 1432,
  "edges_parsed": 8912,
  "total_findings": 27,
  "summary": {"CRITICAL": 2, "HIGH": 9, "MEDIUM": 11, "LOW": 5},
  "findings": [ ... ]
}

Supported Export Formats
SharpHound 2.x / BloodHound CE ({"data": [...], "meta": {"type": ...}} per file, attributes in nested Properties)
Legacy graph JSON (top-level nodes / relationships)
Bare entity lists
UTF-8 BOM handling included
Inline per-object Aces and standalone *_acls.json files are both indexed.

Important Limitations
BloodHound data never contains password hashes — not NTLM, not KRBTGT. Golden Tickets require dumping the KRBTGT hash separately:
bash

impacket-secretsdump.py <domain>/<user>:<pass>@<dc_ip>
Checks are only as complete as the collection that produced the ZIP. If ACL data is missing, DCSync/ACL findings will be empty — re-run SharpHound with -c All (or the equivalent collection methods).
Findings are attack-path opportunities; validate exploitability against your authorized scope before acting.
Remediation Pointers

Finding	Fix
Kerberoasting	Long (25+ char) random passwords on service accounts; use gMSAs
AS-REP Roasting	Re-enable Kerberos pre-auth on all accounts
Unconstrained delegation	Convert to constrained delegation (S4U) or RBCD
DCSync ACLs	Remove unnecessary replication rights from non-DC principals
Privileged accounts	Tiered admin model, mark accounts sensitive, audit adminCount
License
Provided as-is for authorized security assessment use.
