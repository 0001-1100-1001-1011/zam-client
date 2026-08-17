# ZAM Monitoring Agent
# Start: pip install pywin32 && python agent.py

import hashlib
import json
import socket
import platform
import shutil
import subprocess
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path
import time
import win32evtlog
import win32evtlogutil
import win32con
import win32api
import pywintypes
import hmac
import hashlib
import winreg

SECRET = bytes.fromhex("")

# Endpoints
SERVER_URL   = "http://localhost:3000/api/logs"
SOFTWARE_URL = "http://localhost:3000/api/software"
HOSTS_URL    = "http://localhost:3000/api/hosts"

INTERVAL_SEC    = 10
INITIAL_LOGS    = 5
MAX_LOGS        = 100

Last_RecordFile = Path(__file__).parent / "last_record.json"
#Software_RecordFile = Path(__file__).parent / "software_record.json"

HOSTNAME  = socket.gethostname()
CLIENT_ID = hashlib.md5(HOSTNAME.encode()).hexdigest()[:8]
CHANNELS  = ["Application", "System", "Security"]

# Load last record state
def load_state():
    global last_record
    if Last_RecordFile.exists():
        try:
            with open(Last_RecordFile, "r", encoding="utf-8") as f:
                data = json.load(f)
            last_record = {ch: data.get(ch) for ch in CHANNELS}
            return
        except Exception as e:
            print(f"[WARN] Fehler beim Laden: {e}")
    last_record = {ch: None for ch in CHANNELS}

def save_state():
    try:
        with open(Last_RecordFile, "w", encoding="utf-8") as f:
            json.dump(last_record, f)
    except Exception as e:
        print(f"[WARN] Fehler beim Speichern: {e}")

last_record = {ch: None for ch in CHANNELS}

# Mapping Windows Event Types
LEVEL_MAP = {
    win32con.EVENTLOG_INFORMATION_TYPE: "INFO",
    win32con.EVENTLOG_WARNING_TYPE:     "WARNING",
    win32con.EVENTLOG_ERROR_TYPE:       "ERROR",
    win32con.EVENTLOG_AUDIT_SUCCESS:    "INFO",
    win32con.EVENTLOG_AUDIT_FAILURE:    "WARNING",
}

def map_level(event_type):
    return LEVEL_MAP.get(event_type, "INFO")

# Convert Windows Event to JSON
def event_to_dict(ev, channel):
    try:
        message = win32evtlogutil.SafeFormatMessage(ev, channel)
    except Exception:
        message = " ".join(str(s) for s in (ev.StringInserts or [])) or "—"

    try:
        ts = datetime.fromtimestamp(int(ev.TimeGenerated.timestamp())).isoformat()
    except Exception:
        ts = datetime.now().isoformat()

    keyword = ""
    if ev.EventType == win32con.EVENTLOG_AUDIT_FAILURE:
        keyword = "Überwachung gescheitert"
    elif ev.EventType == win32con.EVENTLOG_AUDIT_SUCCESS:
        keyword = "Überwachung erfolgreich"

    return {
        "client_id": CLIENT_ID,
        "hostname": HOSTNAME,
        "time_created": ts,
        "level": map_level(ev.EventType),
        "source": channel,
        "event_source": str(ev.SourceName),
        "event_id": ev.EventID & 0xFFFF,
        "keyword": keyword,
        "message": message.strip().replace("\r\n", " ").replace("\n", " "),
    }

# Read Windows Events
def read_events(channel):
    events = []
    try:
        handle = win32evtlog.OpenEventLog(None, channel)
        flags  = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        raw    = win32evtlog.ReadEventLog(handle, flags, 0)
        win32evtlog.CloseEventLog(handle)

        for ev in raw[:MAX_LOGS]:
            if last_record[channel] is not None and ev.RecordNumber <= last_record[channel]:
                continue
            events.append(event_to_dict(ev, channel))

        if raw:
            last_record[channel] = raw[0].RecordNumber

    except pywintypes.error as e:
        print(f"[WARN] {channel}: {e}")

    return events

#read installed Software
def get_installed_software():
    software = []
    seen = set()

    registry_locations = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]

    for hive, path in registry_locations:
        try:
            with winreg.OpenKey(hive, path) as key:
                for i in range(winreg.QueryInfoKey(key)[0]):
                    subkey_name = winreg.EnumKey(key, i)
                    try:
                        with winreg.OpenKey(key, subkey_name) as subkey:
                            name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                            try:
                                version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                            except FileNotFoundError:
                                version = ""

                            if not name or name in seen:
                                continue
                            seen.add(name)
                            software.append({"name": name, "version": version})
                    except Exception:
                        continue
        except Exception:
            continue

    return sorted(software, key=lambda s: s["name"].lower())

def get_hardware_info():
    info = {
        "hostname":          HOSTNAME,
        "ip_address":        "",
        "cpu_model":         "",
        "ram_size":          0,
        "gpu_model":         "",
        "storage_size":      0,
        "operating_system":  "",
    }

    try:
        info["ip_address"] = socket.gethostbyname(socket.gethostname())
    except socket.error as e:
        print(f"[WARN] IP-Adresse konnte nicht ermittelt werden: {e}")

    try:
        info["operating_system"] = f"{platform.system()} {platform.release()}"
    except Exception as e:
        print(f"[WARN] OS-Info konnte nicht ermittelt werden: {e}")

    try:
        result = subprocess.run(
        ["wmic", "cpu", "get", "name"],
        capture_output=True, text=True, timeout=5, creationflags=subprocess.CREATE_NO_WINDOW
    )
        lines = [l.strip() for l in result.stdout.splitlines() if l.strip() and l.strip() != "Name"]
        info["cpu_model"] = lines[0] if lines else platform.processor()
    except Exception as e:
        print(f"[WARN] CPU-Name konnte nicht ermittelt werden: {e}")


    try:
        mem = win32api.GlobalMemoryStatusEx()
        info["ram_size"] = round(mem["TotalPhys"] / (1024 ** 3))
    except Exception as e:
        print(f"[WARN] RAM-Info konnte nicht ermittelt werden: {e}")

    try:
        total, _, _ = shutil.disk_usage("C:\\")
        info["storage_size"] = round(total / (1024 ** 3))
    except Exception as e:
        print(f"[WARN] Speicherplatz-Info konnte nicht ermittelt werden: {e}")

    info["gpu_model"] = get_gpu_name()


    return info

def get_gpu_name():
    try:
        result = subprocess.run(
            ["wmic", "path", "win32_VideoController", "get", "name"],
            capture_output=True, text=True, timeout=5, creationflags=subprocess.CREATE_NO_WINDOW
        )
        lines = [l.strip() for l in result.stdout.splitlines() if l.strip() and l.strip() != "Name"]

        FAKE_GPUS = [
            "virtual",
            "basic",
            "microsoft",
            "vmware",
            "display",
            "remote"
        ]

        real_gpus = []
        for gpu in lines:
            lower = gpu.lower()
            if not any(bad in lower for bad in FAKE_GPUS):
                real_gpus.append(gpu)

        if real_gpus:
            return real_gpus[0]

        return lines[0] if lines else "unbekannt"

    except Exception as e:
        print(f"[WARN] GPU-Info konnte nicht ermittelt werden: {e}")
        return "unbekannt"

# Send signed JSON payload
def send_signed(url, body):
    payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
    signature = hmac.new(SECRET, payload, hashlib.sha256).hexdigest()

    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "X-Signature": signature,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except urllib.error.URLError as e:
        print(f"[ERROR] {url}: {e.reason}")
        return False

def push_log(log):
    ok = send_signed(SERVER_URL, log)
    if ok:
        ts = log["time_created"][11:19]
        print(f"[{ts}]  {log['level']:<7}  {log['source']:<12}  {log['event_source']:<30}  EventId:{log['event_id']}")
    return ok

def push_software():
    software = get_installed_software()

    body = {
        "hostname": HOSTNAME,
        "software": software,
    }
    ok = send_signed(SOFTWARE_URL, body)
    if ok:
        print(f"[Software] {len(software)} Programme gemeldet")
    return ok

def push_hosts():
    hw = get_hardware_info()
    ok = send_signed(HOSTS_URL, hw)
    if ok:
        print(f"[Hosts] Hardware-Infos gemeldet ({HOSTNAME}, {hw['ip_address']})")
    return ok

def main():
    print("ZAM Monitoring Agent")
    print(f"Hostname  : {HOSTNAME}")
    print(f"Server    : {SERVER_URL}")
    print(f"Intervall : {INTERVAL_SEC}")
    print(f"Kanäle    : {', '.join(CHANNELS)}")

    load_state()

    try:
        already_initialized = any(v is not None for v in last_record.values())

        if already_initialized:
            print("Vorheriger Zustand gefunden, lese neue Events seit letztem Lauf.")
            for channel in CHANNELS:
                print(f"  {channel}: fortgesetzt ab Record #{last_record[channel]}")
                for ev in reversed(read_events(channel)):
                    push_log(ev)
            save_state()
        else:
            print("Starte Log-Lesen")
            for channel in CHANNELS:
                try:
                    handle = win32evtlog.OpenEventLog(None, channel)
                    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                    raw = win32evtlog.ReadEventLog(handle, flags, 0)
                    win32evtlog.CloseEventLog(handle)

                    for ev in reversed(raw[:INITIAL_LOGS]):
                        push_log(event_to_dict(ev, channel))

                    if raw:
                        last_record[channel] = raw[0].RecordNumber
                        save_state()
                        print(f"  {channel}: Start bei Record #{last_record[channel]}")
                except Exception as e:
                    print(f"  {channel}: Zugriff verweigert ({e})")
                    for ev in reversed(read_events(channel)):
                        push_log(ev)

        push_software()
        push_hosts()

    except KeyboardInterrupt:
        print("\n[Agent gestoppt]")

if __name__ == "__main__":
    while True:
        main()
        time.sleep(INTERVAL_SEC)