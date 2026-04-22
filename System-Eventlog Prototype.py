# pip install pywin32

import win32evtlog
import win32evtlogutil
from datetime import datetime
from pathlib import Path
import re

LOG_NAME = "System"
MAX_LOGS = 50

SERVICE_REGEX = re.compile(r"(?i)(Service Name|Dienstname)\s*[:=]\s*(.+)")

def extract_service_name(message: str):
    """Versucht ServiceName aus der Message zu extrahieren."""
    match = SERVICE_REGEX.search(message)
    if match:
        return match.group(2).strip()
    return None

def main():
    handle = win32evtlog.OpenEventLog(None, LOG_NAME)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    events = []
    while len(events) < MAX_LOGS:
        batch = win32evtlog.ReadEventLog(handle, flags, 0)
        if not batch:
            break

        for e in batch:
            msg = win32evtlogutil.SafeFormatMessage(e, LOG_NAME)
            service_name = extract_service_name(msg)

            events.append({
                "Time": e.TimeGenerated.Format(),
                "EventID": e.EventID & 0xFFFF,
                "Level": e.EventType,
                "Source": e.SourceName,
                "ServiceName": service_name,
                "Message": msg.strip(),
            })

            if len(events) >= MAX_LOGS:
                break

    win32evtlog.CloseEventLog(handle)

    lines = []
    for ev in events:
        lines.append(
            f"Time        : {ev['Time']}\n"
            f"EventID     : {ev['EventID']}\n"
            f"Level       : {ev['Level']}\n"
            f"Source      : {ev['Source']}\n"
            f"ServiceName : {ev['ServiceName']}\n"
            f"Message     : {ev['Message']}\n"
            + "-"*80
        )

    date = datetime.now().strftime("%d-%m-%Y_%H-%M")
    path = Path.home() / "Desktop" / f"SystemLog_{date}.txt"
    path.write_text("\n".join(lines), encoding="utf-8")

    print(f"Gespeichert unter:\n{path}")

if __name__ == "__main__":
    main()
