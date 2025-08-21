
import os
import requests
import datetime
import pandas as pd
import urllib3

# Silence TLS warnings due to verify=False (fix certs properly later if possible)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Environment variables from AWX (or set directly for local testing)
ZABBIX_API_URL = os.environ.get('ZABBIX_API_URL')
ZABBIX_API_TOKEN = os.environ.get('ZABBIX_API_TOKEN')
TAG_KEY = os.environ.get('TAG_KEY', 'device')
TAG_VALUE = os.environ.get('TAG_VALUE', 'egw.net')
DAYS = int(os.environ.get('DAYS', '30'))
OUTPUT_FILE = os.environ.get('REPORT_OUTPUT', '/tmp/egw_net_zabbix_report.xlsx')

SEVERITY_MAP = {
    0: "Not classified",
    1: "Information",
    2: "Warning",
    3: "Average",
    4: "High",
    5: "Disaster",
}

def fmt_time(ts: int) -> str:
    try:
        return datetime.datetime.fromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts)

def fmt_duration(seconds: int) -> str:
    seconds = int(seconds)
    h = seconds // 3600
    m = (seconds % 3600) // 60
    s = seconds % 60
    return f"{h:d}:{m:02d}:{s:02d}"

# ---- Helpers ----
def zabbix_api(method, params):
    headers = {
        'Content-Type': 'application/json-rpc',
        'Authorization': f'Bearer {ZABBIX_API_TOKEN}'
    }
    payload = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1,
        "auth": None
    }
    r = requests.post(ZABBIX_API_URL, json=payload, headers=headers, verify=False, timeout=30)
    r.raise_for_status()
    out = r.json()
    if 'error' in out:
        raise RuntimeError(f"Zabbix API error: {out['error']}")
    return out['result']

def epoch_now():
    return int(datetime.datetime.now().timestamp())

def epoch_days_ago(days):
    return int((datetime.datetime.now() - datetime.timedelta(days=days)).timestamp())

# ---- Main data pull ----
def build_dataset():
    # Get hosts with the right tag (include status so we can compute enabled/disabled)
    hosts = zabbix_api('host.get', {
        "output": ["hostid", "name", "status"],
        "selectTags": "extend",
        "tags": [{"tag": TAG_KEY, "value": TAG_VALUE}]
    })

    if not hosts:
        return pd.DataFrame(columns=["Hostname", "Availability %", "Problems Raised", "Total Downtime (min)", "Enabled"]), []

    hostids = [h["hostid"] for h in hosts]
    hostmap = {h["hostid"]: h["name"] for h in hosts}
    host_enabled = {h["hostid"]: (str(h.get("status", "0")) == "0") for h in hosts}  # 0 = enabled, 1 = disabled

    now = epoch_now()
    start = epoch_days_ago(DAYS)

    results = []
    problem_details = []

    for hostid in hostids:
        # Step 1: Get ICMP triggers for this host (include priority for severity)
        triggers = zabbix_api('trigger.get', {
            "hostids": [hostid],
            "output": ["triggerid", "description", "priority"],
            "search": {"description": "Unavailable by ICMP ping"},
            "selectItems": ["itemid", "name", "key_"]
        })
        trig_map = {t["triggerid"]: t for t in triggers}

        icmp_trigger_ids = [t["triggerid"] for t in triggers if t.get("triggerid")]
        problem_count = 0
        downtime_total = 0

        # Step 2: For each ICMP trigger, get all resolved problem events
        for triggerid in icmp_trigger_ids:
            events = zabbix_api('event.get', {
                "output": ["eventid", "clock", "r_eventid", "value"],
                "select_acknowledges": ["clock", "message", "userid", "username", "name", "surname"],
                "source": 0,  # triggers
                "object": 0,  # triggers
                "objectids": [triggerid],
                "time_from": start,
                "time_till": now,
                "value": 1,  # PROBLEM
                "sortfield": ["clock"],
                "sortorder": "ASC"
            })
            for ev in events:
                if ev.get('r_eventid', '0') != "0":
                    resolved_event = zabbix_api('event.get', {
                        "output": ["eventid", "clock"],
                        "eventids": [ev['r_eventid']]
                    })
                    if resolved_event:
                        start_ts = int(ev['clock'])
                        end_ts = int(resolved_event[0]['clock'])
                        down_seconds = end_ts - start_ts
                        if down_seconds > 0:
                            downtime_total += down_seconds
                            problem_count += 1

                            # Extract acknowledges (if any)
                            ack_time = ""
                            ack_notes = ""
                            acks = ev.get("acknowledges", []) or []
                            if acks:
                                acks_sorted = sorted(acks, key=lambda a: int(a.get("clock", 0)))
                                ack_time = fmt_time(acks_sorted[0].get("clock"))

                                note_parts = []
                                for a in acks_sorted:
                                    ts = fmt_time(a.get("clock"))
                                    uname = a.get("username", "")[:2]  # <-- just first two letters
                                    msg = a.get("message", "").strip()
                                    note_parts.append(f"[{ts}] {uname}: {msg}" if msg else f"[{ts}] {uname}")
                                ack_notes = " | ".join(note_parts)

                            trig = trig_map.get(triggerid, {})
                            sev = SEVERITY_MAP.get(int(trig.get("priority", 0)), str(trig.get("priority", 0)))
                            problem_details.append({
                                "Host": hostmap[hostid],
                                "Severity": sev,
                                "Status": "RESOLVED",
                                "Duration": fmt_duration(down_seconds),
                                "Problem": trig.get("description", "Unavailable by ICMP ping"),
                                "Alert Time": fmt_time(start_ts),
                                "Acknowledged time": ack_time,      # <-- new
                                "Recovery time": fmt_time(end_ts),
                                "Notes": ack_notes,                  # <-- new
                            })

        # Step 3: Calculate Availability % using icmpping item history
        availability = 0.0
        icmp_items = zabbix_api('item.get', {
            "output": ["itemid", "name", "hostid", "key_"],
            "hostids": [hostid],
            "search": {"key_": "icmpping"},
            "limit": 1
        })
        if icmp_items:
            itemid = icmp_items[0]["itemid"]
            # Try uint (0) first
            history = zabbix_api('history.get', {
                "output": "extend",
                "history": 0,
                "itemids": [itemid],
                "time_from": start,
                "time_till": now,
                "limit": 100000
            })
            values = [float(h['value']) for h in history]
            # If empty, try float (3)
            if not values:
                history = zabbix_api('history.get', {
                    "output": "extend",
                    "history": 3,
                    "itemids": [itemid],
                    "time_from": start,
                    "time_till": now,
                    "limit": 100000
                })
                values = [float(h['value']) for h in history]
            if values:
                availability = 100.0 * sum(values) / len(values)

        results.append({
            "Hostname": hostmap[hostid],
            "Availability %": round(availability, 2),
            "Problems Raised": problem_count,
            "Total Downtime (min)": round(downtime_total / 60),
            "Enabled": "Yes" if host_enabled.get(hostid, True) else "No"
        })

    df = pd.DataFrame(results)
    if not df.empty:
        df = df.sort_values(by=["Hostname"], kind="stable").reset_index(drop=True)
    return df, problem_details

def write_excel_with_summary(df: pd.DataFrame, problem_details: list, path: str, summary: dict):
    with pd.ExcelWriter(path, engine="xlsxwriter") as writer:
        sheet_name = "Report"

        # Write main results table at row 11
        df.to_excel(writer, sheet_name=sheet_name, startrow=10, index=False)

        workbook  = writer.book
        worksheet = writer.sheets[sheet_name]

        h1 = workbook.add_format({"bold": True, "font_size": 16})
        bold = workbook.add_format({"bold": True})
        pct2 = workbook.add_format({"num_format": "0.00"})
        int_fmt = workbook.add_format({"num_format": "0"})
        normal = workbook.add_format({})

        worksheet.write("A1", f"SLA Availability Report", h1)
        worksheet.write("A2", f"Time Frame: last {DAYS} days", normal)

       

        worksheet.write("B6", "Enabled devices", bold)
        worksheet.write_number("C6", summary["enabled_devices"], int_fmt)

        worksheet.write("D6", "Total devices", bold)
        worksheet.write_number("E6", summary["total_devices"], int_fmt)

        worksheet.write("D1", f"SLI Availability Target", h1)
        worksheet.write("E1", f"95.00", h1)
        worksheet.write("D2", "Total SLA", bold)
         
        worksheet.write_number("E2", summary["avg_enabled_availability"], pct2)

        worksheet.write("B4", "Total problems (all)", bold)
        worksheet.write_number("C4", summary["problems_total"], int_fmt)

        worksheet.write("B5", "Total downtime (min, all)", bold)
        worksheet.write_number("C5", summary["downtime_total_min"], int_fmt)

        worksheet.write("A10", "Devices with < 100% Uptime", bold)

        # Determine where to put the Problem Details section:
        # data_header_row = 10, data_rows = len(df)
        details_start_row = 10 + 1 + len(df) + 5  # +1 for header row, +5 spacer rows

        # Build problem details DataFrame
        details_cols = ["Host", "Severity", "Status", "Duration", "Problem", "Alert Time", "Acknowledged time", "Recovery time", "Notes"]
        df_details = pd.DataFrame(problem_details, columns=details_cols)

        # Write header
        for col_idx, col in enumerate(details_cols):
            worksheet.write(details_start_row, col_idx, col, bold)

        # Write rows
        for r_idx, row in df_details.iterrows():
            for c_idx, col in enumerate(details_cols):
                worksheet.write(details_start_row + 1 + r_idx, c_idx, row[col])

        # Autofit-ish columns across BOTH tables
        combined_cols = list(df.columns)  # main table cols
        for c in details_cols:
            if c not in combined_cols:
                combined_cols.append(c)

        # Compute max width per combined column name across df and df_details
        for col_idx, col in enumerate(df.columns.tolist()):
            width = max(12, min(60, int(max([len(str(col))] + [len(str(v)) for v in df[col].astype(str).tolist()]) * 1.1)))
            worksheet.set_column(col_idx, col_idx, width)

        # For detail columns, set widths appropriately (may overlap indexes if different columns)
        # We'll set based on their index positions starting at 0 as well
        for col_idx, col in enumerate(details_cols):
            col_values = df_details[col].astype(str).tolist() if not df_details.empty else []
            width = max(12, min(80, int(max([len(str(col))] + [len(v) for v in col_values]) * 1.1)))
            worksheet.set_column(col_idx, col_idx, width)

        worksheet.freeze_panes(11, 0)

    return {"summary": summary, "output_file": path}

def main():
    # Build full dataset and collect problem details
    df_full, problem_details = build_dataset()

    # ---- Summary based on ALL devices with the tag ----
    total_devices = len(df_full)
    enabled_count = int((df_full["Enabled"] == "Yes").sum()) if not df_full.empty else 0
    enabled_avail = df_full.loc[df_full["Enabled"] == "Yes", "Availability %"] if not df_full.empty else pd.Series(dtype=float)
    avg_enabled_avail = round(float(enabled_avail.mean()), 2) if not enabled_avail.empty else 0.0
    problems_total = int(df_full["Problems Raised"].sum()) if not df_full.empty else 0
    downtime_total_min = int(df_full["Total Downtime (min)"].sum()) if not df_full.empty else 0

    summary = {
        "total_devices": total_devices,
        "enabled_devices": enabled_count,
        "avg_enabled_availability": avg_enabled_avail,
        "problems_total": problems_total,
        "downtime_total_min": downtime_total_min,
    }

    # ---- Filtering for Excel output ----
    # Keep ONLY hosts that had at least one problem in the window
    if not df_full.empty:
        df_export = df_full[df_full["Problems Raised"] > 0].copy()
        if "Enabled" in df_export.columns:
            df_export.drop(columns=["Enabled"], inplace=True)
    else:
        df_export = df_full

    result = write_excel_with_summary(df_export, problem_details, OUTPUT_FILE, summary)
    print(f"Excel report written to {result['output_file']}")
    print(f"Summary: {result['summary']}")

if __name__ == "__main__":
    main()
