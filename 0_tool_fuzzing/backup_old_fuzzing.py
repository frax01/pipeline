"""Backup the old fuzzing dataset before re-running with FAST-V2.

The pre-2026-05-21 run dropped `server_response` / `success_details` from
the schema, so HC rules in pipeline_fuzzing cannot distinguish VP vs FP
on response-based signals. We're re-running everything; this script
moves the old data out of the way so the fresh run starts clean and the
old post-processed VP/FP can still be referenced.

Local backup (this machine): rename analysisAllData/0_tool_fuzzing
                              → analysisAllData/0_tool_fuzzing.OLD_no_responses

Remote VMs: SSH and rename /home/tecnico/Desktop/Pipeline/0_tool_fuzzing/{exceptions,protocol,fuzzing_*.json}
            → 0_tool_fuzzing/OLD_no_responses_<ts>/ before launching the new run.

    py -X utf8 0_tool_fuzzing/backup_old_fuzzing.py            # local only
    py -X utf8 0_tool_fuzzing/backup_old_fuzzing.py --remote   # also on all 9 VMs
"""
import argparse
import datetime
import shutil
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
LOCAL_SRC = REPO / "analysisAllData" / "0_tool_fuzzing"
LOCAL_DST = REPO / "analysisAllData" / "0_tool_fuzzing.OLD_no_responses"

VM_IPS = [
    "10.79.6.132", "10.79.6.133", "10.79.6.134", "10.79.6.136",
    "10.79.6.137", "10.79.6.138", "10.79.6.139", "10.79.6.141",
    "10.79.6.142",
]
REMOTE_USER = "tecnico"
REMOTE_FUZZING = "/home/tecnico/Desktop/Pipeline/0_tool_fuzzing"


def backup_local() -> None:
    if not LOCAL_SRC.exists():
        print(f"[local] {LOCAL_SRC} does not exist — nothing to back up")
        return
    if LOCAL_DST.exists():
        print(f"[local] {LOCAL_DST} already exists — skipping")
        return
    print(f"[local] {LOCAL_SRC} -> {LOCAL_DST}")
    shutil.move(str(LOCAL_SRC), str(LOCAL_DST))
    print(f"[local] done")


def backup_remote_vm(ip: str, ts: str) -> None:
    backup_dir = f"{REMOTE_FUZZING}/OLD_no_responses_{ts}"
    # Bash here-doc to do everything in one ssh call.
    cmd = (
        f"mkdir -p {backup_dir} && "
        f"for f in exceptions protocol fuzzing_stats.json fuzzing_servers.json; do "
        f"  if [ -e {REMOTE_FUZZING}/$f ]; then "
        f"    mv {REMOTE_FUZZING}/$f {backup_dir}/; "
        f"  fi; "
        f"done && "
        f"ls -la {backup_dir}"
    )
    print(f"[{ip}] backing up to {backup_dir}")
    result = subprocess.run(
        ["ssh", f"{REMOTE_USER}@{ip}", cmd],
        capture_output=True, text=True, timeout=60,
    )
    print(f"[{ip}] rc={result.returncode}")
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(f"[{ip}] stderr: {result.stderr}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--remote", action="store_true",
                    help="Also rename old run on all 9 VMs via SSH")
    ap.add_argument("--local-only-skip", action="store_true",
                    help="Skip local backup (e.g. when only the VMs need it)")
    args = ap.parse_args()

    if not args.local_only_skip:
        backup_local()

    if args.remote:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        for ip in VM_IPS:
            try:
                backup_remote_vm(ip, ts)
            except Exception as e:
                print(f"[{ip}] FAILED: {e}")


if __name__ == "__main__":
    main()
