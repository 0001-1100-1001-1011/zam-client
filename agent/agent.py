#ZAM Monitoring Agent
#Start and install: pip install pywin32 && python agent.py

#Imports
import hashlib
import json
import socket
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path
import time
import win32evtlog
import win32evtlogutil
import win32con
import pywintypes
 
 #Endpoint Definition and Intervalls
SERVER_URL      = "http://localhost:4000/api/logs"
INTERVAL_SEC    = 10
INITIAL_LOGS    = 5
MAX_LOGS        = 100
#Save lastrecord file
Last_RecordFile = Path(__file__).parent / "last_record.json"
 
 #Encode Hostname as MD5
HOSTNAME  = socket.gethostname()
CLIENT_ID = hashlib.md5(HOSTNAME.encode()).hexdigest()[:8]
CHANNELS  = ["Application", "System", "Security"]

#read lastrecord from file
def load_state():
    global last_record
    if Last_RecordFile.exists():
        try:
            with open(Last_RecordFile, "r", encoding="utf-8") as f:
                data = json.load(f)
            last_record = {ch: data.get(ch) for ch in CHANNELS}
            return
        except (json.JSONDecodeError, OSError) as e:
            print(f"[WARN] Fehler beim Laden der letzten Record-Nummern: {e}, starte mit None")
    last_record = {ch: None for ch in CHANNELS}

def save_state():
    try:
        with open(Last_RecordFile, "w", encoding="utf-8") as f:
            json.dump(last_record, f)
    except OSError as e:
        print(f"[WARN] Fehler beim Speichern der letzten Record-Nummern: {e}")

 #last Record Number check
last_record = {ch: None for ch in CHANNELS}

#Mapping Windows Event-Types
LEVEL_MAP = {
    win32con.EVENTLOG_INFORMATION_TYPE: "INFO",
    win32con.EVENTLOG_WARNING_TYPE:     "WARNING",
    win32con.EVENTLOG_ERROR_TYPE:       "ERROR",
    win32con.EVENTLOG_AUDIT_SUCCESS:    "INFO",
    win32con.EVENTLOG_AUDIT_FAILURE:    "WARNING",
}
 #Mapping to Info if Unknwown Type is found
def map_level(event_type):
    return LEVEL_MAP.get(event_type, "INFO")
 
 #Getting text from Windows-Message-DLLs
def event_to_dict(ev, channel):
    try:
        message = win32evtlogutil.SafeFormatMessage(ev, channel)
    except Exception:
        message = " ".join(str(s) for s in (ev.StringInserts or [])) or "—"
 
    try:
        ts = datetime.fromtimestamp(int(ev.TimeGenerated.timestamp())).isoformat()
    except Exception:
        ts = datetime.now().isoformat()
 
 #Create template for JSON
    return {
        "clientId":     CLIENT_ID,
        "hostname":     HOSTNAME,
        "timestamp":    ts,
        "level":        map_level(ev.EventType),
        "source":       channel,
        "event_source":  str(ev.SourceName),
        "eventId":      ev.EventID & 0xFFFF,
        "keyword":      "Überwachung gescheitert" if ev.EventType == win32con.EVENTLOG_AUDIT_FAILURE
                        else ("Überwachung erfolgreich" if ev.EventType == win32con.EVENTLOG_AUDIT_SUCCESS else ""),
        "message":      message.strip().replace("\r\n", " ").replace("\n", " "),
    }
 
 #Open Logs on Localhost and read Logs latest first
def read_events(channel):
    events = []
    try:
        handle = win32evtlog.OpenEventLog(None, channel)
        flags  = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        raw    = win32evtlog.ReadEventLog(handle, flags, 0)
        win32evtlog.CloseEventLog(handle)
 #read MAX_LOGS and skipt duplicates
        for ev in raw[:MAX_LOGS]:
            if last_record[channel] is not None and ev.RecordNumber <= last_record[channel]:
                continue
            events.append(event_to_dict(ev, channel))
 
        if raw:
            last_record[channel] = raw[0].RecordNumber
 #Warning if not Admin
    except pywintypes.error as e:
        print(f"[WARN] {channel}: {e}")
 
    return events
 
 #Convert to JSON-String and Header Post-Request
def push_log(log):
    payload = json.dumps(log).encode("utf-8")
    req = urllib.request.Request(
        SERVER_URL,
        data=payload,
        headers={"Content-Type": "application/json", "X-Client-Id": CLIENT_ID},
        method="POST",
    )
    #Send Request, 5 second timeout and Console-formatting
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status == 200:
                ts = log["timestamp"][11:19]
                print(f"[{ts}]  {log['level']:<7}  {log['source']:<12}  {log['event_source']:<30}  EventId:{log['eventId']}")
                return True
    except urllib.error.URLError as e:
        print(f"[ERROR] {e.reason}")
    return False
 
 #Agent start Info
def main():
    print("ZAM Monitoring Agent")
    print(f"Client-ID : {CLIENT_ID}")
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

                    # Push last 5 instantly
                    for ev in reversed(raw[:INITIAL_LOGS]):
                        push_log(event_to_dict(ev, channel))

                    if raw:
                        last_record[channel] = raw[0].RecordNumber
                        save_state()
                        print(f"  {channel}: Start bei Record #{last_record[channel]}")
                except pywintypes.error as e:
                    print(f"  {channel}: Zugriff verweigert ({e})")
                    for ev in reversed(read_events(channel)):
                        push_log(ev)
    except KeyboardInterrupt:
        print("\n[Agent gestoppt]")
 
if __name__ == "__main__":
        #while True:
         main()
         #time.sleep(INTERVAL_SEC) #use only without Task Scheduler