import subprocess, json, time
def run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except Exception as e:
        return 'ERR ' + str(e)

MONGO = '/elkeid/mongodb/mongodb_4.2/bin/mongo'
URI = 'mongodb://elkeid:190f54c6ddq10r3k6k@127.0.0.1:27017/elkeid?authSource=elkeid'

now = int(time.time())
def cve(cveid, title, desc, severity, cwe, vtype, threat, solution):
    return {
        "cve": cveid, "title_en": title, "title_cn": title, "description_en": desc, "description_cn": desc,
        "severity": severity, "cwe_id": cwe, "vuln_type_en": vtype, "threat_type_en": threat,
        "solution_en": solution, "solution_cn": solution,
        "cvss3_vector": "", "cvss2_vector": "", "cnnvd": "", "cnvd": "",
        "create_time": now, "update_time": now, "last_modified_time": now, "published_time": now,
        "has_payload": 0, "has_exploit": 0, "is_verified": 1, "is_wild_exploited": 0,
        "vuln_references": "https://nvd.nist.gov/vuln/detail/" + cveid,
        "payload_link": "", "exploit_link": "", "vuln_software": "", "platform": "",
        "safe_version": "", "variant": "", "bvd": "", "action": "block"
    }

cv = [
    cve("CVE-2024-6387", "OpenSSH regreSSHion RCE", "OpenSSH signal handler race condition leading to unauthenticated remote code execution as root.", "5", "CWE-362", "Race Condition", "Network", "Upgrade OpenSSH to 9.8p1 or later."),
    cve("CVE-2022-0847", "Dirty Pipe LPE", "Linux kernel pipe buffer flaw allowing overwrite of read-only files leading to local privilege escalation.", "4", "CWE-269", "Privilege Escalation", "System", "Upgrade kernel to 5.16.11 / 5.15.25 / 5.10.102 or later."),
    cve("CVE-2024-1086", "nf_tables UAF LPE", "Linux kernel netfilter nf_tables use-after-free leading to local privilege escalation (CISA KEV).", "5", "CWE-416", "Use After Free", "System", "Upgrade kernel to 5.15.149 / 6.1.76 or later."),
    cve("CVE-2023-0386", "OverlayFS LPE", "Linux kernel OverlayFS flaw allowing local privilege escalation via setuid file.", "4", "CWE-269", "Privilege Escalation", "System", "Upgrade kernel to 6.2 or apply backport patch."),
    cve("CVE-2024-3094", "XZ Utils backdoor", "Malicious backdoor in xz/liblzma 5.6.0/5.6.1 allowing SSH authentication bypass and RCE.", "5", "CWE-506", "Backdoor", "System", "Downgrade xz to 5.6.0 earlier safe version."),
    cve("CVE-2021-44228", "Log4Shell RCE", "Apache Log4j2 JNDI injection allowing unauthenticated remote code execution.", "5", "CWE-917", "Code Injection", "Network", "Upgrade Log4j to 2.17.0 or later."),
    cve("CVE-2024-2961", "glibc iconv RCE", "glibc iconv buffer overflow allowing code execution when converting to ISO-2022-CN-EXT.", "4", "CWE-120", "Buffer Overflow", "System", "Upgrade glibc to patched version."),
    cve("CVE-2025-37750", "SMB client UAF", "Linux kernel SMB client use-after-free vulnerability.", "4", "CWE-416", "Use After Free", "Network", "Upgrade kernel to patched version."),
]

js = json.dumps(cv)
open('/tmp/cve.json','w').write(js)
print(run(['docker','cp','/tmp/cve.json','ab26241257bb:/tmp/cve.json']))

ev = ('var a=JSON.parse(cat("/tmp/cve.json")); '
      'a.forEach(function(x){db.vuln_info.deleteOne({cve:x.cve}); db.vuln_info.insertOne(x);}); '
      'print("imported cv es="+a.length+", total vuln_info="+db.vuln_info.count())')
print(run(['docker','exec','ab26241257bb',MONGO,URI,'--quiet','--eval',ev]))
