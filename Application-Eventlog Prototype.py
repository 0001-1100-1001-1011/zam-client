#before runinning please use ->
#pip install pywin32  make Windows-API call possible with python

import win32evtlog
import win32evtlogutil
from datetime import datetime
from pathlib import Path

# Category Application, Security, System etc.
LOG_NAME = "Application"
MAX_LOGS = 20 # Numer of last created logs to read


def fetch_events(log_name: str, count: int) -> list[dict]:
    handle = win32evtlog.OpenEventLog(None, log_name)
    flags  = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    events = []
    while len(events) < count:
        batch = win32evtlog.ReadEventLog(handle, flags, 0)
        if not batch:
            break
        for e in batch:
            events.append({
                "TimeCreated"  : e.TimeGenerated.Format(),
                "EventID"      : e.EventID & 0xFFFF,          # Remove Severity-Bits
                "Level"        : e.EventType,
                "Source"       : e.SourceName,
                "Message"      : win32evtlogutil.SafeFormatMessage(e, log_name),
            })
            if len(events) >= count:
                break

    win32evtlog.CloseEventLog(handle)
    return events

def format_events(events: list[dict]) -> str:
    lines = []
    for e in events:
        lines.append(
            f"TimeCreated : {e['TimeCreated']}\n"
            f"EventID     : {e['EventID']}\n"
            f"Level       : {e['Level']}\n"
            f"Source      : {e['Source']}\n"
            f"Message     : {e['Message']}\n"
            f"{'-' * 80}"
        )
    return "\n".join(lines)

def main():
    print(f"Letzten {MAX_LOGS} Events aus '{LOG_NAME}' exportiert")
    events   = fetch_events(LOG_NAME, MAX_LOGS)
    text     = format_events(events)

    date_str = datetime.now().strftime("%d-%m-%Y_%H-%M")
    out_path = Path.home() / "Desktop" / f"{LOG_NAME}_EventLog_{date_str}.txt" #Change Path to appropriate Localtion
    out_path.write_text(text, encoding="utf-8")

    print(f"Gespeichert unter:\n{out_path}")

if __name__ == "__main__":
    main()