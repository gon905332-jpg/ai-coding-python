import requests
import sys
import urllib3
import re
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import threading

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ================== Configuration ==================
MAX_WORKERS = 20          # Number of concurrent threads (adjust based on network bandwidth)
TIMEOUT = 8               # Timeout in seconds for each request
# ================== End of Configuration ==================

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
    pattern = r'^7\.(0\.[0-6]|2\.[0-8]|4\.[0-2]|6\.[0-3])'
    return bool(re.match(pattern, ver_str))

def check_single_target(target):
    target = target.rstrip("/")
    result = {"target": target, "vulnerable": False, "version": "unknown", "details": ""}

    try:
        # Basic FMC detection
        r = requests.get(f"{target}/", verify=False, timeout=10, allow_redirects=True)
        body = r.text.lower()
        if "firewall management center" not in body and "fmc" not in body:
            result["details"] = "Does not appear to be a Cisco FMC"
            return result

        vulnerable = False
        detected_version = "unknown"
        hit_paths = []

        for path in PROBE_PATHS:
            try:
                url = f"{target}{path}"
                r = requests.get(url, verify=False, timeout=TIMEOUT)
                if r.status_code == 200:
                    vulnerable = True
                    hit_paths.append(path)
                    if "serverversion" in path:
                        try:
                            data = r.json()
                            detected_version = data.get("serverVersion", "unknown")
                        except:
                            pass
            except:
                continue

        result["vulnerable"] = vulnerable
        result["version"] = detected_version
        if vulnerable:
            status = "[CRITICAL] Vulnerable" if is_vulnerable_version(detected_version) else "[!] 200 OK (needs verification)"
            result["details"] = f"{status} - Hit paths: {hit_paths} - Version: {detected_version}"
        else:
            result["details"] = "Patched or not vulnerable"

        return result

    except Exception as e:
        result["details"] = f"Error: {str(e)}"
        return result

def main():
    if len(sys.argv) != 2:
        print(f"Usage: python3 {Path(sys.argv[0]).name} targets.txt")
        sys.exit(1)

    target_file = Path(sys.argv[1])
    if not target_file.exists():
        print(f"[-] File not found: {target_file}")
        sys.exit(1)

    with open(target_file, "r", encoding="utf-8") as f:
        targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    if not targets:
        print("[-] No valid URLs found in targets.txt")
        sys.exit(1)

    print(f"[*] Starting bulk parallel check for CVE-2026-20079 (Cisco FMC Auth Bypass)")
    print(f"[*] Targets: {len(targets)}  |  Concurrent workers: {MAX_WORKERS}\n")

    vulnerable_list = []
    lock = threading.Lock()

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_target = {executor.submit(check_single_target, t): t for t in targets}
        
        for future in tqdm(as_completed(future_to_target), total=len(targets), desc="Scanning progress"):
            result = future.result()
            with lock:
                if result["vulnerable"]:
                    vulnerable_list.append(result)
                print(f"\n{result['target']}")
                print(f"   → {result['details']}")

    # Save results
    with open("result_vulnerable.txt", "w", encoding="utf-8") as f:
        for v in vulnerable_list:
            f.write(f"{v['target']} | {v['version']} | {v['details']}\n")

    with open("result_summary.log", "w", encoding="utf-8") as f:
        f.write(f"Scan date: {len(targets)} targets checked, {len(vulnerable_list)} potentially vulnerable\n")
        f.write("="*80 + "\n")
        for v in vulnerable_list:
            f.write(f"{v['target']} → {v['details']}\n")

    print("\n" + "="*70)
    print(f"[*] Scan completed - Total targets: {len(targets)} | Potentially vulnerable: {len(vulnerable_list)}")
    if vulnerable_list:
        print("   Details saved to: result_vulnerable.txt")
    print("   Full summary saved to: result_summary.log")
    print("="*70)

if __name__ == "__main__":
    main()
