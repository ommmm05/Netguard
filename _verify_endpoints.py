import httpx

endpoints = [
    "/api/health",
    "/api/dashboard/overview",
    "/api/dashboard/stats",
    "/api/dashboard/config",
    "/api/visibility/summary",
    "/api/visibility/hosts",
    "/api/visibility/flows",
    "/api/visibility/graph",
    "/api/visibility/dns",
    "/api/visibility/arp-tls",
    "/api/visibility/patterns",
    "/api/detection/status",
    "/api/detection/alerts",
    "/api/forensics/iocs",
    "/api/forensics/incidents",
    "/api/forensics/export/csv",
]

base = "http://127.0.0.1:8000"
ok = 0
fail = 0
for e in endpoints:
    try:
        r = httpx.get(base + e, timeout=10)
        status = r.status_code
        label = "OK" if status == 200 else f"FAIL({status})"
        if status == 200:
            ok += 1
        else:
            fail += 1
        print(f"  {label}  {e}")
    except Exception as ex:
        fail += 1
        print(f"  ERR   {e} — {ex}")

print(f"\n{ok}/{ok+fail} endpoints OK")
