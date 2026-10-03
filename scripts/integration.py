import json, os, time, uuid, urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
BASE = os.getenv("BASE_URL", "http://localhost:18000/api")
TOKEN = os.getenv("API_TOKEN", "local-development-token")
def call(path, data=None):
    request=urllib.request.Request(BASE+path, data=json.dumps(data).encode() if data is not None else None, headers={"Authorization":"Bearer "+TOKEN,"Content-Type":"application/json"})
    with urllib.request.urlopen(request) as r:
        return json.load(r)
def main():
    assert call("/health")["status"] == "ok"
    call("/demo", {})
    found=call("/incidents")
    assert {"failed_logins","success_after_failures","suspicious_http","server_errors"} <= {i["detector"] for i in found}
    id="integration-"+uuid.uuid4().hex[:8]
    service=call("/services",{"name":id,"importance":4})
    source=call("/sources",{"name":"Integration synthetic","service_id":service["id"]})
    now=datetime.now(timezone.utc)
    events=[{"event_id":id+"-"+str(n),"timestamp":(now-timedelta(seconds=10-n)).isoformat(),"status":200,"path":"/integration","synthetic":True} for n in range(10)]
    with ThreadPoolExecutor(max_workers=5) as pool:
        replies=list(pool.map(lambda _:call("/ingest/"+source["id"],events),range(5)))
    assert sum(r["accepted"] for r in replies)==10,replies
    assert sum(r["duplicates"] for r in replies)==40,replies
    before=next(s for s in call("/sources") if s["id"]=="vector-demo")["accepted"]
    vector_events=[{"event_id":id+"-vector-"+str(n),"timestamp":datetime.now(timezone.utc).isoformat(),"status":200,"path":"/vector-integration","synthetic":True} for n in range(3)]
    Path("demo/logs/integration.jsonl").open("a").write("".join(json.dumps(e)+"\n" for e in vector_events))
    for _ in range(20):
        source_state=next(s for s in call("/sources") if s["id"]=="vector-demo")
        if source_state["accepted"]>=before+3:
            break
        time.sleep(1)
    assert source_state["accepted"]>=before+3, source_state
    print("PASS: PostgreSQL demo, four detectors, concurrent replay (10 accepted / 40 duplicates), Vector file -> HTTP ingestion")
if __name__=="__main__":
    main()
