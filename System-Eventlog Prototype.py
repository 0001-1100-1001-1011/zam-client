# please use
# pip install pywin32
# if not installed before

import win32evtlog
import win32evtlogutil
import json
from datetime import datetime
from pathlib import Path

LOG_NAME = "System"
MAX_LOGS = 20


def fetch_events(log_name: str, count: int) -> list[dict]:
    handle = win32evtlog.OpenEventLog(None, log_name)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    events = []
    while len(events) < count:
        batch = win32evtlog.ReadEventLog(handle, flags, 0)
        if not batch:
            break

        for e in batch:
            events.append({
                "TimeCreated": e.TimeGenerated.Format(),
                "EventID": e.EventID & 0xFFFF,
                "Level": e.EventType,
                "Source": e.SourceName,
                "Message": win32evtlogutil.SafeFormatMessage(e, log_name),
            })

            if len(events) >= count:
                break

    win32evtlog.CloseEventLog(handle)
    return events


def save_json(events: list[dict], log_name: str):
    date_str = datetime.now().strftime("%d-%m-%Y_%H-%M")
    out_path = Path.home() / "Desktop" / f"{log_name}_EventLog_{date_str}.json"

    with out_path.open("w", encoding="utf-8") as f:
        json.dump(events, f, indent=4, ensure_ascii=False)

    print(f"JSON gespeichert unter:\n{out_path}")


def main():
    print(f"Exportiere die letzten {MAX_LOGS} Events aus '{LOG_NAME}' ...")
    events = fetch_events(LOG_NAME, MAX_LOGS)
    save_json(events, LOG_NAME)


if __name__ == "__main__":
    main()
