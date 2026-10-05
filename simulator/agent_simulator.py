"""Submits deterministic demo attempts. It does not execute any action locally."""
import argparse, json, urllib.request
SCENARIOS=[("READ","src/login.js",{}),("READ","src/auth.js",{}),("READ",".env",{}),("READ","~/.ssh/id_rsa",{}),("READ","passport.pdf",{}),("EXECUTE","npm test",{}),("EXECUTE","rm -rf /",{}),("NETWORK_CONNECT","telemetry.unknown.example",{"host":"telemetry.unknown.example"})]
def post(url,body):
    req=urllib.request.Request(url,data=json.dumps(body).encode(),headers={"Content-Type":"application/json"})
    with urllib.request.urlopen(req,timeout=10) as response:return json.load(response)
def main():
    p=argparse.ArgumentParser();p.add_argument("--api",default="http://127.0.0.1:8000/api");p.add_argument("--task-id");args=p.parse_args()
    task_id=args.task_id or post(args.api+"/tasks",{"name":"Simulator security demo","description":"Safe runtime policy demonstration"})["task_id"]
    for kind,resource,metadata in SCENARIOS:
        result=post(args.api+"/actions/check",{"task_id":task_id,"agent":"simulator","action_type":kind,"resource":resource,"metadata":metadata})
        print(f"{kind:15} {resource:35} {result['decision']:9} {result['risk_level']}")
if __name__=="__main__":main()
