import json, subprocess, sys, requests
from typing import List, Dict, Tuple, Optional

OSV_ENDPOINT = "https://api.osv.dev/v1/query"
SEVERITY_ORDER = {"CRITICAL":4,"HIGH":3,"MODERATE":2,"MEDIUM":2,"LOW":1,"NONE":0}

def _run(cmd: List[str]) -> Tuple[int,str,str]:
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = p.communicate()
    return p.returncode, out, err

def docker_available() -> bool:
    code,_,_ = _run(["docker","version","--format","{{.Server.Version}}"])
    return code == 0

def image_exists(image: str) -> bool:
    code,out,_ = _run(["docker","images","-q",image])
    return code == 0 and out.strip() != ""

def pull_image(image: str):
    print(f"[INFO] Pulling {image} ...")
    code,_,err = _run(["docker","pull",image])
    if code != 0:
        print(err, file=sys.stderr); sys.exit(2)

def _exec(image: str, shell_cmd: str):
    code,out,err = _run(["docker","run","--rm",image,"sh","-lc",shell_cmd])
    if code != 0:
        code2,out2,err2 = _run(["docker","run","--rm",image,"bash","-lc",shell_cmd])
        if code2 != 0: return code, (err or err2)
        return 0, out2
    return 0, out

def detect_pkg_manager(image: str) -> str:
    for name,cmd in {"dpkg":"dpkg","apk":"apk","rpm":"rpm"}.items():
        c,o = _exec(image, f"command -v {cmd} >/dev/null 2>&1 && echo {name} || true")
        if c == 0 and name in o: return name
    return "unknown"

def list_packages(image: str, mgr: str):
    if mgr == "dpkg": cmd = "dpkg -l | awk 'NR>5 {print \" \"}' || true"
    elif mgr == "apk": cmd = "apk info -v || true"
    elif mgr == "rpm": cmd = "rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\\n' || true"
    else: return []
    c,out = _exec(image, cmd)
    if c != 0: return []
    pkgs=[]
    for line in out.splitlines():
        parts=line.strip().split()
        if parts: pkgs.append((parts[0], parts[1] if len(parts)>1 else None))
    return pkgs

def query_osv(pkg: str, version: Optional[str]):
    payload = {"package":{"name":pkg}}
    if version: payload["version"]=version
    try:
        r = requests.post(OSV_ENDPOINT, json=payload, timeout=15)
        if r.status_code == 200:
            d = r.json()
            return d.get("vulns") or d.get("vulnerabilities") or []
    except Exception:
        pass
    return []

def max_severity(vulns: List[Dict]) -> str:
    max_s=0
    for v in vulns:
        label = (v.get("database_specific",{}) or {}).get("severity")
        if label:
            max_s = max(max_s, SEVERITY_ORDER.get(str(label).upper(),0))
        else:
            s = (v.get("summary","") or "").lower()
            if "critical" in s: max_s = max(max_s, 4)
            elif "high" in s:   max_s = max(max_s, 3)
    for k,val in SEVERITY_ORDER.items():
        if val == max_s: return k
    return "NONE"

def scan_image(image: str, fail_on: str="HIGH") -> int:
    if not docker_available():
        print("[ERROR] Docker not available.", file=sys.stderr); return 2
    if not image_exists(image): pull_image(image)
    mgr = detect_pkg_manager(image); print(f"[INFO] Package manager: {mgr}")
    pkgs = list_packages(image, mgr)
    if not pkgs: print("[WARN] No packages found (maybe distroless)."); return 0
    print(f"[INFO] Packages discovered: {len(pkgs)}")
    findings=[]
    for name,ver in pkgs:
        vulns = query_osv(name,ver)
        if vulns:
            sev = max_severity(vulns)
            ids = [v.get("id") or "UNKNOWN" for v in vulns][:3]
            findings.append((name,ver,sev,ids))
    if not findings:
        print("[OK] No vulnerabilities found."); return 0
    order = SEVERITY_ORDER
    findings.sort(key=lambda x: order.get(x[2],0), reverse=True)
    print("\nPACKAGE\tVERSION\tSEVERITY\tEXAMPLES"); print("-"*72)
    for n,v,s,ids in findings: print(f"{n}\t{v or '-'}\t{s}\t{', '.join(ids)}")
    if order.get(findings[0][2],0) >= order.get(fail_on.upper(),3):
        print(f"\n[FAIL] Highest severity >= {fail_on}. Blocking build."); return 1
    print("\n[PASS] No findings above policy threshold."); return 0

if __name__=="__main__":
    import argparse
    p=argparse.ArgumentParser(description="Container Image Vulnerability Scanner (Docker + OSV)")
    p.add_argument("--image", required=True, help="e.g. ubuntu:22.04")
    p.add_argument("--fail-on", default="HIGH", help="LOW|MEDIUM|HIGH|CRITICAL")
    a=p.parse_args(); sys.exit(scan_image(a.image, a.fail_on))
