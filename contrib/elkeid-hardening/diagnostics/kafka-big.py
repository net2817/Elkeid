import subprocess
def run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except Exception as e:
        return 'ERR ' + str(e)

cmd = ('export PATH=/elkeid/kafka/jdk-17.0.1/bin:$PATH; '
       '/elkeid/kafka/kafka_2.13-3.2.3/bin/kafka-console-consumer.sh '
       '--bootstrap-server 127.0.0.1:9092 --topic hids_svr --max-messages 2000 --timeout-ms 15000 '
       '--consumer.config /tmp/kafka_client.properties 2>/dev/null '
       '| grep -aoE "test3|10-11-69-16|elkeid-5" | sort | uniq -c')
print('=== hids_svr 2000-msg hostname counts ===')
print(run(['docker','exec','ab26241257bb','bash','-c',cmd]))
