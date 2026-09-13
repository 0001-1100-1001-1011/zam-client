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
import winreg
import ssl

AGENT_KEY = Path(r"C:\Zam-Projekt\zam-client\agent\agent.key")

QUEUE_FILE = Path(__file__).parent / "event_queue.json"

def load_queue():
    if not QUEUE_FILE.exists():
        return []
    try:
        return json.loads(QUEUE_FILE.read_text())
    except:
        return []

def save_queue(queue):
    tmp = QUEUE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(queue, indent=2))
    tmp.replace(QUEUE_FILE)

def add_to_queue(event):
    queue = load_queue()
    queue.append(event)
    save_queue(queue)

def send_queue():
    queue = load_queue()
    if not queue:
        return

    print(f"[Queue] {len(queue)} gespeicherte Events gefunden.")

    remaining = []
    for ev in queue:
        if push_log(ev):
            ts = ev["time_created"][11:19]
            print(f"[Queue] [{ts}] {ev['level']} {ev['source']} EventId:{ev['event_id']}")
        else:
            remaining.append(ev)

    save_queue(remaining)

def load_key():
    try:
        key_hex = AGENT_KEY.read_text().strip()
        return bytes.fromhex(key_hex)
    except Exception:
        return None

SECRET = load_key()

SERVER_URL   = "https://10.72.100.25/agent-api/logs"
SOFTWARE_URL = "https://10.72.100.25/agent-api/softwares"
HOSTS_URL    = "https://10.72.100.25/agent-api/hosts"

INTERVAL_SEC    = 10
INITIAL_LOGS    = 5
MAX_LOGS        = 500

Last_RecordFile = Path(__file__).parent / "last_record.json"

HOSTNAME  = socket.gethostname()
CLIENT_ID = hashlib.sha256(HOSTNAME.encode()).hexdigest()[:32]
CHANNELS  = ["Application", "System", "Security"]

CONFIG_FILE = Path(__file__).parent / "certs.json"

def load_config():
    if CONFIG_FILE.exists():
        return json.loads(CONFIG_FILE.read_text())
    return {}

cfg = load_config()

TLS_CERT_FILE = cfg["cert"]
TLS_KEY_FILE  = cfg["key"]
TLS_CA_FILE   = cfg["ca"]

def build_ssl_context():
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=TLS_CA_FILE)
    ctx.load_cert_chain(certfile=TLS_CERT_FILE, keyfile=TLS_KEY_FILE)
    return ctx

def load_state():
    global last_record
    if Last_RecordFile.exists():
        try:
            with open(Last_RecordFile, "r", encoding="utf-8") as f:
                data = json.load(f)
            last_record = {ch: data.get(ch) for ch in CHANNELS}
            return
        except Exception:
            pass
    last_record = {ch: None for ch in CHANNELS}

def save_state():
    try:
        with open(Last_RecordFile, "w", encoding="utf-8") as f:
            json.dump(last_record, f)
    except Exception:
        pass

last_record = {ch: None for ch in CHANNELS}

LEVEL_MAP = {
    win32con.EVENTLOG_INFORMATION_TYPE: "INFO",
    win32con.EVENTLOG_WARNING_TYPE:     "WARNING",
    win32con.EVENTLOG_ERROR_TYPE:       "ERROR",
    win32con.EVENTLOG_AUDIT_SUCCESS:    "INFO",
    win32con.EVENTLOG_AUDIT_FAILURE:    "WARNING",
}

def map_level(event_type):
    return LEVEL_MAP.get(event_type, "INFO")

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

    except pywintypes.error:
        pass

    return events

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

                            try:
                                name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                            except Exception:
                                continue

                            if not name or name.strip() == "" or name in seen:
                                continue

                            try:
                                version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                            except FileNotFoundError:
                                version = "unknown"

                            if not version or version.strip() == "":
                                version = "unknown"

                            seen.add(name)
                            software.append({"name": name, "version": version})

                    except Exception:
                        continue
        except Exception:
            continue

    return sorted(software, key=lambda s: s["name"].lower())

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

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
        info["ip_address"] = get_local_ip()
    except Exception:
        pass

    try:
        info["operating_system"] = f"{platform.system()} {platform.release()}"
    except Exception:
        pass

    try:
        result = subprocess.run(
            ["powershell", "-Command", "(Get-CimInstance Win32_Processor).Name"],
            capture_output=True, text=True, timeout=5, creationflags=subprocess.CREATE_NO_WINDOW
        )
        lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
        info["cpu_model"] = lines[0] if lines else platform.processor()
    except Exception:
        pass

    try:
        mem = win32api.GlobalMemoryStatusEx()
        info["ram_size"] = round(mem["TotalPhys"] / (1024 ** 3))
    except Exception:
        pass

    try:
        total, _, _ = shutil.disk_usage("C:\\")
        info["storage_size"] = round(total / (1024 ** 3))
    except Exception:
        pass

    info["gpu_model"] = get_gpu_name()

    return info

def get_gpu_name():
    try:
        result = subprocess.run(
            ["powershell", "-Command", "(Get-CimInstance Win32_VideoController).Name"],
            capture_output=True, text=True, timeout=5, creationflags=subprocess.CREATE_NO_WINDOW
        )
        lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]

        FAKE_GPUS = ["virtual", "basic", "microsoft", "vmware", "display", "remote"]

        real_gpus = []
        for gpu in lines:
            lower = gpu.lower()
            if not any(bad in lower for bad in FAKE_GPUS):
                real_gpus.append(gpu)

        if real_gpus:
            return real_gpus[0]

        return lines[0] if lines else "unbekannt"

    except Exception:
        return "unbekannt"

def send_signed(url, body, retries=3):
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

    backoff = 2

    for attempt in range(1, retries + 1):
        try:
            ctx = build_ssl_context()

            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                return resp.status == 200
        except urllib.error.HTTPError as e:
            error_body = e.read().decode("utf-8", errors="replace")
            if attempt < retries:
                time.sleep(backoff)
                backoff *= 2
        except Exception as e:
            if attempt < retries:
                time.sleep(backoff)
                backoff *= 2
    return False

def push_log(log):
    ok = send_signed(SERVER_URL, log)
    if ok:
        ts = log["time_created"][11:19]
        print(f"[{ts}]  {log['level']:<7}  {log['source']:<12}  {log['event_source']:<30}  EventId:{log['event_id']}")
    return ok

def push_software():
    software = get_installed_software()
    body = {"hostname": HOSTNAME, "software": software}
    ok = send_signed(SOFTWARE_URL, body)
    if ok:
        print(f"[Software] {len(software)} Programme gemeldet")
    return ok

def push_hosts():
    hw = get_hardware_info()
    hw["hmac_key"] = SECRET.hex()
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

    send_queue()
    try:
        already_initialized = any(v is not None for v in last_record.values())

        if already_initialized:
            print("Vorheriger Zustand gefunden, lese neue Events seit letztem Lauf.")
            for channel in CHANNELS:
                print(f"  {channel}: fortgesetzt ab Record #{last_record[channel]}")
                for ev in reversed(read_events(channel)):
                    if not push_log(ev):
                        add_to_queue(ev)
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
                        ev_dict = event_to_dict(ev, channel)
                        if not push_log(ev_dict):
                            add_to_queue(ev_dict)
                        time.sleep(0.05)

                    if raw:
                        last_record[channel] = raw[0].RecordNumber
                        save_state()
                        print(f"  {channel}: Start bei Record #{last_record[channel]}")
                except Exception:
                    for ev in reversed(read_events(channel)):
                        if not push_log(ev):
                            add_to_queue(ev)
                        time.sleep(0.05)
        
        queue_software()
        time.sleep(0.2)
        send_software_queue()
        time.sleep(0.2)

        push_hosts()
        time.sleep(0.2)
    except KeyboardInterrupt:
        print("\n[Agent gestoppt]")

if __name__ == "__main__":
    #while True:
        main()
     #   time.sleep(INTERVAL_SEC) only without Taskscheduler
