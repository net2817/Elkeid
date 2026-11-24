import json, subprocess, time
def run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except Exception as e:
        return 'ERR ' + str(e)

kev = json.load(open('/root/cisa_kev.json'))
vulns = kev.get('vulnerabilities', [])
print('CISA KEV total:', len(vulns))

now = int(time.time())
cves = []
for v in vulns:
    cwe = v.get('cwes', [''])[0] if v.get('cwes') else ''
    cves.append({
        "cve": v['cveID'],
        "title_en": v.get('vulnerabilityName', v['cveID']),
        "title_cn": v.get('vulnerabilityName', v['cveID']),
        "description_en": v.get('shortDescription', ''),
        "description_cn": v.get('shortDescription', ''),
        "severity": "5",
        "cwe_id": cwe,
        "vuln_type_en": v.get('product', ''),
        "threat_type_en": "Network",
        "solution_en": v.get('requiredAction', ''),
        "solution_cn": v.get('requiredAction', ''),
        "cvss3_vector": "", "cvss2_vector": "", "cnnvd": "", "cnvd": "",
        "create_time": now, "update_time": now, "last_modified_time": now, "published_time": now,
        "has_payload": 0, "has_exploit": 1, "is_verified": 1,
        "is_wild_exploited": 1 if v.get('knownRansomwareCampaignUse') == 'Known' else 0,
        "vuln_references": "https://nvd.nist.gov/vuln/detail/" + v['cveID'],
        "payload_link": "", "exploit_link": "", "vuln_software": v.get('product', ''),
        "platform": "", "safe_version": "", "variant": "", "bvd": "", "action": "block"
    })

json.dump(cves, open('/root/cisa_kev_converted.json','w'))
print('converted:', len(cves))
run(['sshpass','-p','Admin@123456','scp','-o','StrictHostKeyChecking=no','/root/cisa_kev_converted.json','root@10.255.255.249:/tmp/cisa_kev_converted.json'])
print('copied to 249')
