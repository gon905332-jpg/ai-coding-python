import requests
import sys
import urllib3
import re
import json

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PROBE_PATHS = [
    "/api/fmc_platform/v1/info/serverversion",
    "/api/fmc_platform/v1/info/system",
    "/api/fmc_platform/v1/info/server",
    "/rest/fmc_platform/v1/info/server",
    "/api/fmc_platform/v1/domains"
]

def is_vulnerable_version(ver_str):
    if not ver_str or ver_str == "unknown":
        return False
    # Vulnerable ranges: 7.0.0-7.0.6 / 7.2.0-7.2.8 / 7.4.0-7.4.2 / 7.6.0-7.6.3
    pattern = r'^7\.(0\.[0-6]|2\.[0-8]|4\.[0-2]|6\.[0-3])'
    return bool(re.match(pattern, ver_str))

def check_cve_2026_20079(target):
    target = target.rstrip("/")
    print(f"[*] Checking {target} for CVE-2026-20079 (Cisco FMC Auth Bypass)")

    try:
        # Basic FMC detection
        r = requests.get(f"{target}/", verify=False, timeout=10, allow_redirects=True)
        body = r.text.lower()
        if "firewall management center" not in body and "fmc" not in body:
            print("[-] Target does not appear to be a Cisco FMC device.")
            return False

        print("[+] Cisco FMC interface detected.")

        vulnerable = False
        detected_version = "unknown"

        # Probe all known leaky endpoints
        for path in PROBE_PATHS:
            try:
                url = f"{target}{path}"
                r = requests.get(url, verify=False, timeout=8)
                
                if r.status_code == 200:
                    print(f"[!!!] VULNERABLE HIT: {path} → 200 OK")
                    vulnerable = True
                    
                    # Extract version if this is the serverversion endpoint
                    if "serverversion" in path:
                        try:
                            data = r.json()
                            detected_version = data.get("serverVersion", "unknown")
                            print(f"    Detected version: {detected_version}")
                        except:
                            print("    JSON parse failed, but 200 OK → still suspicious")
                    
                    # Show response snippet
                    print(f"    Snippet: {r.text[:200].replace('\n',' ')}...")
                    
            except requests.exceptions.RequestException as e:
                print(f"[?] {path} → Error: {e}")
                continue

        # Final version-based confirmation
        if vulnerable:
            if is_vulnerable_version(detected_version):
                print("\n[CRITICAL] This FMC is in CVE-2026-20079 vulnerable range (version match confirmed)!!")
            else:
                print("\n[!] 200 OK received, but version appears patched? (possible false positive)")
            print("    Isolate and patch IMMEDIATELY - high risk level")
        else:
            print("\n[+] All endpoints required authentication → Patched or not vulnerable")

        return vulnerable

    except Exception as e:
        print(f"[-] Fatal error: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} https://<fmc-host>")
        sys.exit(1)
    check_cve_2026_20079(sys.argv[1])

