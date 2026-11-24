import subprocess, json, time
def run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except Exception as e:
        return 'ERR ' + str(e)

MONGO = '/elkeid/mongodb/mongodb_4.2/bin/mongo'
URI = 'mongodb://elkeid:190f54c6ddq10r3k6k@127.0.0.1:27017/elkeid?authSource=elkeid'

def fc(t, cn_title, en_title, param, filter_, result, cn_desc, en_desc):
    return '''  -
    check_id: %d
    type: "%s"
    title: "%s"
    title_cn: "%s"
    description_cn: "%s"
    description: "%s"
    solution: "edit the config file to set the recommended value"
    solution_cn: "编辑配置文件并设置为推荐值"
    security: "high"
    type_cn: "安全加固"
    check:
      rules:
        - type: "file_line_check"
          param:
            - "%s"
          filter: '%s'
          result: '%s'
''' % (t, "Identification", en_title, cn_title, cn_desc, en_desc, param, filter_, result)

yaml_content = '''baseline_id: 6000
baseline_version: 1.0
baseline_name: "社区 Linux 安全加固基线"
baseline_name_en: "Community Linux Hardening Baseline"
system:
  - "centos"
  - "ubuntu"
  - "debian"
check_list:
''' + (
    fc(1, "SSH 禁止 root 登录", "Disable SSH root login", "/etc/ssh/sshd_config", r'^\s*PermitRootLogin\s+(\w+)', '$(==)no', "禁止 root 直接 SSH 登录", "Disable SSH root login") +
    fc(2, "SSH 禁用空密码", "Disable SSH empty password", "/etc/ssh/sshd_config", r'^\s*PermitEmptyPasswords\s+(\w+)', '$(==)no', "禁用 SSH 空密码登录", "Disable SSH empty password") +
    fc(3, "SSH 使用协议 2", "SSH Protocol 2", "/etc/ssh/sshd_config", r'^\s*Protocol\s+(\d+)', '$(==)2', "SSH 仅使用协议版本 2", "Use SSH protocol version 2 only") +
    fc(4, "忽略广播 ICMP", "Ignore ICMP broadcast", "/etc/sysctl.conf", r'^\s*net\.ipv4\.icmp_echo_ignore_broadcasts\s*=\s*(\d+)', '$(==)1', "忽略广播 ICMP 请求", "Ignore broadcast ICMP requests") +
    fc(5, "开启 SYN Cookie", "Enable SYN cookies", "/etc/sysctl.conf", r'^\s*net\.ipv4\.tcp_syncookies\s*=\s*(\d+)', '$(==)1', "开启 TCP SYN Cookie 防护", "Enable TCP SYN cookies")
)

open('/tmp/baseline-6000.yaml','w').write(yaml_content)
print(run(['docker','cp','/tmp/baseline-6000.yaml','ab26241257bb:/elkeid/manager/conf/baseline_config/6000.yaml']))

now = int(time.time())
info = {"baseline_id": 6000, "baseline_version": "1.0",
        "baseline_name": "社区 Linux 安全加固基线", "baseline_name_en": "Community Linux Hardening Baseline",
        "check_id_list": [1,2,3,4,5], "system_list": ["centos","ubuntu","debian"],
        "update_time": now, "last_check_time": now}
js = json.dumps(info)
open('/tmp/baseline-info.json','w').write(js)
print(run(['docker','cp','/tmp/baseline-info.json','ab26241257bb:/tmp/baseline-info.json']))

ev = ('var j=JSON.parse(cat("/tmp/baseline-info.json")); '
      'db.baseline_info.deleteOne({baseline_id:6000}); db.baseline_info.insertOne(j); '
      'print("baseline 6000 inserted, total baseline_info="+db.baseline_info.count())')
print(run(['docker','exec','ab26241257bb',MONGO,URI,'--quiet','--eval',ev]))
print(run(['docker','exec','ab26241257bb','bash','-c','ls /elkeid/manager/conf/baseline_config/']))
