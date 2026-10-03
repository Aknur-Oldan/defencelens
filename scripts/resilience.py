import json, subprocess, time, urllib.request, uuid
from datetime import datetime, timezone
from integration import call, BASE, TOKEN

def compose(*args):
    subprocess.run(["docker","compose",*args],check=True,capture_output=True)
def upload():
    result=subprocess.run(["curl","--fail-with-body","-sS","-H","Authorization: Bearer "+TOKEN,
        "-F","file=@/tmp/defencelens-redis.tar",BASE+"/scans"],capture_output=True,text=True,check=True)
    return json.loads(result.stdout)
try:
    compose("stop","worker","redis")
    system=call("/system")
    assert system["redis"]=="unavailable",system
    event={"event_id":"outage-"+uuid.uuid4().hex,"timestamp":datetime.now(timezone.utc).isoformat(),
           "status":200,"path":"/outage-test","synthetic":True}
    assert call("/ingest/vector-demo",[event])["accepted"]==1
    scan=upload()
    assert scan["status"]=="pending"
    time.sleep(6)
    assert call("/scans/"+scan["id"])["status"]=="pending"
    print("PASS: basic ingestion while Redis is down; image upload persisted as pending")
finally:
    compose("up","-d","redis","worker")
for _ in range(60):
    result=call("/scans/"+scan["id"])
    if result["status"] in ("completed","failed"):
        break
    time.sleep(2)
assert result["status"]=="completed",result
print("PASS: durable outbox automatically recovered after Redis restart; real Trivy scan completed")
