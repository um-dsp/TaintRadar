import os
import subprocess

base_sqlmap_logs = "/home/umd-user/Downloads/taintradar-joern-taint-radar/taint-radar/output/paths/sqlmap_logs"
base_sql_injection_cves = "/home/umd-user/Downloads/taintradar-joern-taint-radar/taint-radar/output/paths/sql_injection_cves"

author = "Anonymous"

# Iterate over each subfolder in sql_injection_cves
for folder in os.listdir(base_sql_injection_cves):
    folder_path = os.path.join(base_sql_injection_cves, folder)
    if os.path.isdir(folder_path):
        logs_dir = os.path.join(base_sqlmap_logs, folder+"-output")
        out_dir = folder_path
        vendor_meta = os.path.join(folder_path, "vendor.json")

        # Only run if logs_dir exists
        if os.path.exists(logs_dir):
            cmd = [
                "python3", "/home/umd-user/Downloads/taintradar-joern-taint-radar/taint-radar/output/paths/cve_gen.py",
                "--logs-dir", logs_dir,
                "--out-dir", out_dir,
                "--author", author,
                "--vendor-meta", vendor_meta
            ]
            print(f"[+] Running for: {folder}")
            subprocess.run(cmd)
        else:
            print(f"[!] Skipping {folder} — logs dir not found: {logs_dir}")

