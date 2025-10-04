import re, sys
from pathlib import Path
RULES=[
 (re.compile(r'^\s*ADD\s', re.I|re.M), "Use COPY instead of ADD unless necessary (CIS 4.2)"),
 (re.compile(r'^\s*USER\s+root', re.I|re.M), "Avoid running as root; set a non-root USER (CIS 5.28)"),
 (re.compile(r':latest\b'), "Pin image tags (avoid :latest)"),
 (re.compile(r'curl\s+\|\s*sh'), "Avoid piping curl to shell; verify signatures"),
 (re.compile(r'^\s*EXPOSE\s+.*\b0\b', re.I|re.M), "Avoid exposing 0 (all ports)")
]
RECOMMEND=[
 (re.compile(r'^\s*HEALTHCHECK\b', re.I|re.M), "Add HEALTHCHECK to detect run-time issues"),
 (re.compile(r'^\s*COPY\s+--chown=', re.I|re.M), "Prefer COPY --chown to avoid post-copy chown")
]
def check(path: Path)->int:
    text=path.read_text(encoding="utf-8", errors="ignore"); failed=False
    print(f"[INFO] Scanning Dockerfile: {path}")
    for pat,msg in RULES:
        if pat.search(text): print(f"[WARN] {msg}"); failed=True
    for pat,msg in RECOMMEND:
        if not pat.search(text): print(f"[INFO] Suggestion: {msg}")
    print("[FAIL] Insecure patterns found.") if failed else print("[PASS] No insecure patterns detected.")
    return 1 if failed else 0
if __name__=="__main__":
    import argparse
    p=argparse.ArgumentParser(description="Dockerfile static analysis")
    p.add_argument("--file", default="Dockerfile"); a=p.parse_args()
    sys.exit(check(Path(a.file)))
