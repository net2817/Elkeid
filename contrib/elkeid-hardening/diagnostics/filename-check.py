import subprocess
def run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except Exception as e:
        return 'ERR ' + str(e)

cmd = ('export PATH=/elkeid/kafka/jdk-17.0.1/bin:$PATH; '
       '/elkeid/kafka/kafka_2.13-3.2.3/bin/kafka-console-consumer.sh '
       '--bootstrap-server 127.0.0.1:9092 --topic hids_svr --max-messages 3000 --timeout-ms 20000 '
       '--consumer.config /tmp/kafka_client.properties 2>/dev/null > /tmp/hids2.bin; '
       'echo "filename count: $(grep -ac filename /tmp/hids2.bin)"; '
       'echo "flags count: $(grep -ac flags /tmp/hids2.bin)"; '
       'echo "file count: $(grep -ac file /tmp/hids2.bin)"; '
       'echo "test3 count: $(grep -ac test3 /tmp/hids2.bin)"; '
       'echo "--- sample lines containing filename ---"; grep -a filename /tmp/hids2.bin | head -2 | strings | head -20')
print(run(['docker','exec','ab26241257bb','bash','-c',cmd]))
