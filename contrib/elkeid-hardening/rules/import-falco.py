import subprocess, json
def run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except Exception as e:
        return 'ERR ' + str(e)

MONGO = '/elkeid/mongodb/mongodb_4.2/bin/mongo'
URI = 'mongodb://elkeid:190f54c6ddq10r3k6k@127.0.0.1:27017/elkeid?authSource=elkeid'

def mknode(part, vtype, value):
    return {"CheckDataType":"static","Value":value,"Part":part,"Group":"","Type":vtype,"Extra":{},"Separator":"","LogicType":""}

def mkrule(rule_id, rule_name, harm, part, regex_val, desc, attack_id, suggestion):
    return {
        "RuleId": rule_id, "RuleName": rule_name, "CEP": "", "AlertData": True, "Del": "",
        "Action": {"Extra": {}, "Persistent": False, "Name": ""},
        "Append": [
            {"RelyPart":"","AppendFieldName":"alert_type_us","ConnID":"","CacheTTL":"","Extra":{},"Value":"execution","Type":"STATIC"},
            {"CacheTTL":"","Extra":{},"Value":attack_id,"Type":"STATIC","RelyPart":"","AppendFieldName":"attack_id_list","ConnID":""},
            {"RelyPart":"","AppendFieldName":"suggestion","ConnID":"","CacheTTL":"","Extra":{},"Value":suggestion,"Type":"STATIC"},
        ],
        "Filter": {"Value":"59","Part":"data_type","Type":""},
        "Search": None,
        "CheckList": {"CheckNodes":[mknode(part,"REGEX",regex_val)],"ForEach":"","CEP":""},
        "Desc": {"KillChainID":"persistent","Value":desc,"AffectedTarget":"host_process"},
        "Threshold": None, "Type": "Detection", "NodeDesignate": {"Nodes": []},
        "HarmLevel": harm, "AlertEmail": "", "Author": "falco-adapted", "Modify": {"Extra": {}, "Name": ""}
    }

rules = [
    mkrule("nc_remote_code_execution", "Netcat RCE", "high", "argv",
           "(?:\\bnc\\b|\\bncat\\b).*(?:-e\\s|-c\\s|--sh-exec|--exec|--lua-exec)",
           "Netcat runs with remote code execution flags", "T1059", "check nc/ncat process with -e/-c flags"),
    mkrule("search_private_keys", "Search private keys or passwords", "medium", "argv",
           "(?:grep|find|egrep).*(?:id_rsa|id_dsa|id_ed25519|id_ecdsa|BEGIN.{0,20}PRIVATE)",
           "Search private keys or passwords via grep/find", "T1552", "check the process searching for private keys"),
    mkrule("remove_bulk_data", "Remove bulk data from disk", "high", "exe",
           "(?:\\bshred\\b|\\bmkfs\\b|\\bmke2fs\\b)",
           "Bulk data removal via shred/mkfs", "T1485", "check the data destruction process"),
    mkrule("execution_from_dev_shm", "Execution from /dev/shm", "high", "argv",
           "(?:/dev/shm/)",
           "File execution from /dev/shm (fileless or tmp exec)", "T1059", "check the process executed from /dev/shm"),
    mkrule("find_aws_credentials", "Find AWS credentials", "medium", "argv",
           "(?:aws_access_key_id|aws_secret_access_key|accesskeyid|secretaccesskey|\\.aws/credentials)",
           "Search for AWS credentials", "T1552", "check the process searching for AWS credentials"),
    mkrule("clear_log_activities", "Clear log activities", "medium", "argv",
           "(?:\\brm\\b.*(?:/var/log|/dev/log)|\\btruncate\\b.*\\.log|\\bdd\\b.*of=/var/log)",
           "Clear or truncate critical log files", "T1070", "check the process clearing log files"),
    mkrule("python_reverse_shell", "Python reverse shell", "high", "argv",
           "(?:python\\d*).*(?:socket|subprocess).*(?:connect|dup2)",
           "Python reverse shell one-liner", "T1059", "check the python reverse shell process"),
    mkrule("suspicious_php_webshell", "Suspicious PHP webshell", "medium", "argv",
           "(?:\\bphp\\b).*(?:eval\\s*\\(|base64_decode|system\\s*\\(|shell_exec)",
           "Suspicious PHP code execution pattern", "T1505", "check the PHP webshell execution"),
    mkrule("suspicious_encoded_command", "Suspicious encoded command", "medium", "argv",
           "(?:base64\\s+-d|\\|\\s*base64\\s+-d|echo.{0,20}\\|\\s*(?:sh|bash))",
           "Base64 encoded command execution", "T1059", "check the encoded command execution"),
    mkrule("suspicious_privilege_escalation_command", "Suspicious privilege escalation", "high", "argv",
           "(?:\\bchmod\\b.*(?:u\\+s|[0-7]{3,4})|\\bchown\\b.*\\broot\\b|\\bsetuid\\b)",
           "Suspicious privilege escalation via chmod/chown/setuid", "T1548", "check the privilege escalation command"),
]

def to_xml(rules):
    parts = ['<root ruleset_id="falco_adapted_detect" ruleset_name="falco_adapted_detect" type="Rule" undetected_discard="true">']
    for r in rules:
        parts.append('  <rule rule_id="%s" type="Detection" author="falco-adapted">' % r['RuleId'])
        parts.append('    <rule_name>%s</rule_name>' % r['RuleName'])
        parts.append('    <harm_level>%s</harm_level>' % r['HarmLevel'])
        parts.append('    <filter part="data_type">59</filter>')
        parts.append('    <check_list>')
        for n in r['CheckList']['CheckNodes']:
            parts.append('      <check_node part="%s" type="REGEX" check_data_type="static">%s</check_node>' % (n['Part'], n['Value']))
        parts.append('    </check_list>')
        parts.append('    <alert_data>true</alert_data>')
        parts.append('    <modify></modify><del></del><action></action>')
        parts.append('    <desc affected_target="host_process">%s</desc>' % r['Desc']['Value'])
        parts.append('  </rule>')
    parts.append('</root>')
    return '\n'.join(parts)

ruleset = {
    "Encrypted": False, "CipherText": "", "RuleSetID": "falco_adapted_detect",
    "Json": {
        "Type":"Rule","TaskID":"","EnableCompressIndex":False,"RulesetName":"falco_adapted_detect",
        "Version":"","Debug":False,"RulesetId":"falco_adapted_detect","FullCollectRules":"",
        "Rules": rules, "CompressConf":{}, "UndetectedDiscard": True
    },
    "Xml": to_xml(rules)
}

js = json.dumps(ruleset)
open('/tmp/ruleset.json','w').write(js)
print(run(['docker','cp','/tmp/ruleset.json','ab26241257bb:/tmp/ruleset.json']))

ev = ('var j=JSON.parse(cat("/tmp/ruleset.json")); '
      'db.hub_ruleset_stable_elkeid_hub.deleteOne({RuleSetID:"falco_adapted_detect"}); '
      'db.hub_ruleset_stable_elkeid_hub.insertOne(j); '
      'db.hub_ruleset_cache_elkeid_hub.deleteOne({RuleSetID:"falco_adapted_detect"}); '
      'db.hub_ruleset_cache_elkeid_hub.insertOne(j); '
      'print("inserted falco_adapted_detect, rules="+j.Json.Rules.length)')
print(run(['docker','exec','ab26241257bb',MONGO,URI,'--quiet','--eval',ev]))
print(run(['docker','exec','ab26241257bb',MONGO,URI,'--quiet','--eval','print("stable="+db.hub_ruleset_stable_elkeid_hub.count()+", cache="+db.hub_ruleset_cache_elkeid_hub.count())']))
