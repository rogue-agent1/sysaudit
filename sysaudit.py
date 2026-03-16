#!/usr/bin/env python3
"""sysaudit - Quick macOS system security & hygiene audit. Zero deps."""
import subprocess, sys, os, json, re
from datetime import datetime

def run(cmd, shell=False):
    r = subprocess.run(cmd if not shell else cmd, shell=shell, capture_output=True, text=True, timeout=10)
    return r.stdout.strip()

def check(name, ok, detail=""):
    status = "✅" if ok else "⚠️"
    print(f"  {status} {name}" + (f" — {detail}" if detail else ""))
    return 1 if ok else 0

def audit_firewall():
    print("\n🔥 Firewall")
    fw = run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
    return check("Firewall", "enabled" in fw.lower(), fw.split(".")[-1].strip() if "." in fw else fw)

def audit_filevault():
    print("\n🔒 FileVault")
    fv = run(["/usr/bin/fdesetup", "status"])
    return check("FileVault", "On" in fv, fv)

def audit_sip():
    print("\n🛡️ System Integrity Protection")
    sip = run(["/usr/bin/csrutil", "status"])
    return check("SIP", "enabled" in sip.lower(), sip.split(":")[-1].strip() if ":" in sip else sip)

def audit_gatekeeper():
    print("\n🚪 Gatekeeper")
    gk = run(["/usr/sbin/spctl", "--status"])
    return check("Gatekeeper", "enabled" in gk.lower() or "assessments enabled" in gk.lower(), gk)

def audit_updates():
    print("\n📦 Software Updates")
    try:
        upd = run(["softwareupdate", "-l"], shell=False)
        no_updates = "No new software available" in upd or "No updates" in upd
        return check("Up to date", no_updates, "all current" if no_updates else "updates available")
    except: return check("Updates check", False, "timed out")

def audit_ssh():
    print("\n🔑 SSH")
    score = 0
    ssh_dir = os.path.expanduser("~/.ssh")
    if os.path.isdir(ssh_dir):
        keys = [f for f in os.listdir(ssh_dir) if f.endswith(".pub")]
        score += check("SSH keys", len(keys) > 0, f"{len(keys)} key pair(s)")
        for k in keys:
            priv = os.path.join(ssh_dir, k[:-4])
            if os.path.exists(priv):
                mode = oct(os.stat(priv).st_mode)[-3:]
                score += check(f"  {k[:-4]} permissions", mode == "600", f"mode {mode}")
    else:
        check("SSH directory", False, "~/.ssh not found")
    remote = run(["/usr/sbin/systemsetup", "-getremotelogin"], shell=False)
    score += check("Remote Login (SSH)", "Off" in remote, remote.split(":")[-1].strip() if ":" in remote else remote)
    return score

def audit_sharing():
    print("\n📡 Sharing Services")
    score = 0
    for svc in ["remoteappleevents", "remotelogin"]:
        out = run(["/usr/sbin/systemsetup", f"-get{svc}"])
        off = "Off" in out or "off" in out
        score += check(svc, off, "disabled" if off else "ENABLED")
    return score

def audit_users():
    print("\n👤 Users")
    users = run("dscl . -list /Users | grep -v '^_'", shell=True).splitlines()
    real = [u for u in users if u not in ("daemon","nobody","root")]
    return check("User accounts", len(real) <= 3, f"{len(real)} accounts: {', '.join(real)}")

def audit_listening():
    print("\n🌐 Listening Ports")
    out = run("/usr/sbin/lsof -iTCP -sTCP:LISTEN -n -P 2>/dev/null | tail -n+2", shell=True)
    ports = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 9:
            port_part = parts[8].split(":")[-1]
            ports.add(f"{parts[0]}:{port_part}")
    if ports:
        for p in sorted(ports): print(f"    📌 {p}")
    return check("Listening services", len(ports) < 10, f"{len(ports)} services")

def main():
    print("🔍 macOS System Audit")
    print(f"   {datetime.now().strftime('%Y-%m-%d %H:%M')} | {run(['sw_vers', '--productVersion'])} | {run(['hostname'])}")
    
    total = 0
    total += audit_firewall()
    total += audit_filevault()
    total += audit_sip()
    total += audit_gatekeeper()
    total += audit_ssh()
    total += audit_sharing()
    total += audit_users()
    total += audit_listening()
    
    print(f"\n{'='*40}")
    print(f"Score: {total} checks passed")
    print("Run with --json for machine-readable output")

if __name__ == "__main__":
    main()
