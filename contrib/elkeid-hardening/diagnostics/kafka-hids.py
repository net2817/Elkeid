import subprocess
def run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except Exception as e:
        return 'ERR ' + str(e)

base = ('export PATH=/elkeid/kafka/jdk-17.0.1/bin:$PATH; '
        '/elkeid/kafka/kafka_2.13-3.2.3/bin/kafka-topics.sh --bootstrap-server 127.0.0.1:9092 --list 2>&1')
print('=== kafka topics ===')
print(run(['docker','exec','ab26241257bb','bash','-c',base]))

cmd = ('export PATH=/elkeid/kafka/jdk-17.0.1/bin:$PATH; '
       '/elkeid/kafka/kafka_2.13-3.2.3/bin/kafka-console-consumer.sh '
       '--bootstrap-server 127.0.0.1:9092 --topic hids --max-messages 200 --timeout-ms 6000 '
       '--consumer.config /tmp/kafka_client.properties 2>/dev/null '
       '| grep -aoE "test3|10-11-69-16|elkeid-5" | sort | uniq -c')
print('=== hids topic hostname counts ===')
print(run(['docker','exec','ab26241257bb','bash','-c',cmd]))
