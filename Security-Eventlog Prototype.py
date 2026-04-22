# pip install pywin32

import win32evtlog
import win32evtlogutil
from datetime import datetime
from pathlib import Path
import xml.etree.ElementTree as ET

LOG_NAME = "Security"
MAX_LOGS = 100

def extract_security_fields(event):
    """Extrahiert Security-EventData aus XML."""
    try:
        xml = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
        root = ET.fromstring(xml)

        data = {}
        for d in root.findall(".//EventData/Data"):
            name = d.attrib.get("Name", "Unknown")
            data[name] = d.text

        return data
    except:
        return {}

def main():
    handle = win32evtlog.OpenEventLog(None, LOG_NAME)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    events = []

    while len(events) < MAX_LOGS:
        batch = win32evtlog.ReadEventLog(handle, flags, 0)
        if not batch:
            break

        for e in batch:
            xml_data = extract_security_fields(e)
            msg = win32evtlogutil.SafeFormatMessage(e, LOG_NAME)

            events.append({
                "Time": e.TimeGenerated.Format(),
                "EventID": e.EventID & 0xFFFF,
                "Source": e.SourceName,
                "Message": msg.strip(),
                **xml_data
            })

            if len(events) >= MAX_LOGS:
                break

    win32evtlog.CloseEventLog(handle)

    lines = []
    for ev in events:
        for k, v in ev.items():
            lines.append(f"{k:20}: {v}")
        lines.append("-" * 90)

    date = datetime.now().strftime("%d-%m-%Y_%H-%M")
    path = Path.home() / "Desktop" / f"SecurityLog_{date}.txt"
    path.write_text("\n".join(lines), encoding="utf-8")

    print(f"Gespeichert unter:\n{path}")

if __name__ == "__main__":
    main()
