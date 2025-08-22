import os
import re
import requests
import datetime
import pandas as pd
import urllib3
import yaml

# Silence TLS warnings due to verify=False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# -------- Environment --------
ZABBIX_API_URL = os.environ.get('ZABBIX_API_URL')
ZABBIX_API_TOKEN = os.environ.get('ZABBIX_API_TOKEN')
TAG_KEY = os.environ.get('TAG_KEY', 'device')  # e.g. "device" or "sla_report_code"
DAYS = int(os.environ.get('DAYS', '30'))
OUTPUT_FILE = os.environ.get('REPORT_OUTPUT', '/tmp/zabbix_sla_report.xlsx')
SLA_CODES_FILE = os.environ.get('SLA_CODES_FILE', '/runner/artifacts/sla_codes.yml')

SEVERITY_MAP = {
    0: "Not classified",
    1: "Information",
    2: "Warning",
    3: "Average",
    4: "High",
    5: "Disaster",
}

# -------- Utilities --------
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

def epoch_now():
    return int(datetime.datetime.now().timestamp())

def epoch_days_ago(days):
    return int((datetime.datetime.now() - datetime.timedelta(days=days)).timestamp())

def zabbix_api(method, params):
    headers = {
        'Content-Type': 'application/json-rpc',
        'Authorization': f'Bearer {ZABBIX_API_TOKEN}',
    }
    payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1, "auth": None}
    r = requests.post(ZABBIX_API_URL, json=payload, headers=headers, verify=False, timeout=60)
    r.raise_for_status()
    out = r.json()
    if 'error' in out:
        raise RuntimeError(f"Zabbix API error: {out['error']}")
    return out['result']

def sanitize_sheet_name(name: str) -> str:
    # Excel worksheet name cannot contain : \ / ? * [ ]
    # and must be at most 31 chars
    name = re.sub(r'[:\\/?*\[\]]', '_', name)
    return name[:31]

# -------- Data builders --------
def build_dataset_for_code(tag_value: str):
    """
    Returns:
      df (DataFrame): columns [Hostname, Availability %, Problems Raised, Total Downtime (min), Enabled]
      problem_details (list[dict]): for the "Problem details" table
    """
    hosts = zabbix_api('host.get', {
        "output": ["hostid", "name", "status"],
        "selectTags": "extend",
        "tags": [{"tag": TAG_KEY, "value": tag_value}]
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
        # ICMP triggers
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

        # Events with acknowledges
        for triggerid in icmp_trigger_ids:
            events = zabbix_api('event.get', {
                "output": ["eventid", "clock", "r_eventid", "value"],
                "select_acknowledges": ["clock", "message", "userid", "username", "name", "surname"],
                "source": 0,     # triggers
                "object": 0,     # triggers
                "objectids": [triggerid],
                "time_from": start,
                "time_till": now,
                "value": 1,      # PROBLEM
                "sortfield": ["clock"],
                "sortorder": "ASC"
            })

            for ev in events:
                r_evid = ev.get('r_eventid', '0')
                if r_evid and str(r_evid) != "0":
                    resolved_event = zabbix_api('event.get', {
                        "output": ["eventid", "clock"],
                        "eventids": [r_evid]
                    })
                    if resolved_event:
                        start_ts = int(ev['clock'])
                        end_ts = int(resolved_event[0]['clock'])
                        down_seconds = end_ts - start_ts
                        if down_seconds > 0:
                            downtime_total += down_seconds
                            problem_count += 1

                            # Acks (compact notes)
                            ack_time = ""
                            ack_notes = ""
                            acks = ev.get("acknowledges", []) or []
                            if acks:
                                acks_sorted = sorted(acks, key=lambda a: int(a.get("clock", 0)))
                                ack_time = fmt_time(acks_sorted[0].get("clock"))
                                note_parts = []
                                for a in acks_sorted:
                                    ts = fmt_time(a.get("clock"))
                                    uname2 = (a.get("username") or "")[:2]  # first two letters only
                                    msg = (a.get("message") or "").strip()
                                    note_parts.append(f"[{ts}] {uname2}: {msg}" if msg else f"[{ts}] {uname2}")
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
                                "Acknowledged time": ack_time,
                                "Recovery time": fmt_time(end_ts),
                                "Notes": ack_notes,
                            })

        # Availability % from icmpping history
        availability = 0.0
        icmp_items = zabbix_api('item.get', {
            "output": ["itemid", "name", "hostid", "key_"],
            "hostids": [hostid],
            "search": {"key_": "icmpping"},
            "limit": 1
        })
        if icmp_items:
            itemid = icmp_items[0]["itemid"]
            # Unsigned ints first
            history = zabbix_api('history.get', {
                "output": "extend",
                "history": 0,
                "itemids": [itemid],
                "time_from": start,
                "time_till": now,
                "limit": 100000
            })
            values = [float(h['value']) for h in history]
            if not values:
                # Float fallback
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

# -------- Excel writers --------
def write_sheet(df: pd.DataFrame,
                problem_details: list,
                writer: pd.ExcelWriter,
                summary: dict,
                sheet_title: str):
    """Write the main table + summary + problem details to an existing ExcelWriter."""
    # Double-sanitize just in case caller forgot
    sheet_name = sanitize_sheet_name(sheet_title)

    df.to_excel(writer, sheet_name=sheet_name, startrow=10, index=False)

    workbook  = writer.book
    worksheet = writer.sheets[sheet_name]

    h1 = workbook.add_format({"bold": True, "font_size": 16})
    bold = workbook.add_format({"bold": True})
    pct2 = workbook.add_format({"num_format": "0.00"})
    int_fmt = workbook.add_format({"num_format": "0"})

    # Headers & summary
    worksheet.write("A1", f"SLA Availability Report — {sheet_title}", h1)
    worksheet.write("A3", f"Time Frame: last {DAYS} days")

    worksheet.write("B6", "Enabled devices", bold)
    worksheet.write_number("C6", summary["enabled_devices"], int_fmt)

    worksheet.write("D6", "Total devices", bold)
    worksheet.write_number("E6", summary["total_devices"], int_fmt)

    worksheet.write("D2", "Avg Availability (Enabled)", bold)
    worksheet.write_number("E2", summary["avg_enabled_availability"], pct2)

    worksheet.write("B4", "Total problems (all)", bold)
    worksheet.write_number("C4", summary["problems_total"], int_fmt)

    worksheet.write("B5", "Total downtime (min, all)", bold)
    worksheet.write_number("C5", summary["downtime_total_min"], int_fmt)

    worksheet.write("A10", "Devices with < 100% Uptime", bold)

    # Problem details: leave 5 blank rows after the data table
    details_start_row = 10 + 1 + len(df) + 5  # header row + spacer
    details_cols = [
        "Host", "Severity", "Status", "Duration",
        "Problem", "Alert Time", "Acknowledged time", "Recovery time", "Notes"
    ]
    df_details = pd.DataFrame(problem_details, columns=details_cols)

    # Write detail header
    for col_idx, col in enumerate(details_cols):
        worksheet.write(details_start_row, col_idx, col, bold)

    # Write detail rows
    for r_idx, row in df_details.iterrows():
        for c_idx, col in enumerate(details_cols):
            worksheet.write(details_start_row + 1 + r_idx, c_idx, row[col])

    # Column widths for main table
    for col_idx, col in enumerate(df.columns.tolist()):
        width = max(12, min(60, int(max([len(str(col))] + [len(str(v)) for v in df[col].astype(str).tolist()]) * 1.1)))
        worksheet.set_column(col_idx, col_idx, width)

    # Column widths for details
    for col_idx, col in enumerate(details_cols):
        col_values = df_details[col].astype(str).tolist() if not df_details.empty else []
        width = max(12, min(80, int(max([len(str(col))] + [len(v) for v in col_values]) * 1.1)))
        worksheet.set_column(col_idx, col_idx, width)

    worksheet.freeze_panes(11, 0)

def write_summary_sheet(writer: pd.ExcelWriter, rows: list):
    """Create/overwrite a 'Summary' sheet listing Group and Avg Availability (Enabled)."""
    sheet_name = "Summary"
    df_sum = pd.DataFrame(rows, columns=["Group", "Avg Availability (Enabled)"])
    # Sort alphabetically by group name (change to ascending by availability if you prefer)
    df_sum.sort_values(by="Group", inplace=True, kind="stable")
    df_sum.reset_index(drop=True, inplace=True)

    df_sum.to_excel(writer, sheet_name=sheet_name, startrow=0, index=False)

    workbook = writer.book
    ws = writer.sheets[sheet_name]

    h1 = workbook.add_format({"bold": True, "font_size": 16})
    pct2 = workbook.add_format({"num_format": "0.00"})

    ws.write("A1", "SLA Availability Summary", h1)

    # Adjust widths
    max_w0 = max([len("Group")] + [len(str(x)) for x in df_sum["Group"].astype(str).tolist()]) if not df_sum.empty else len("Group")
    ws.set_column(0, 0, min(50, max(15, int(max_w0 * 1.1))))
    ws.set_column(1, 1, 22, pct2)
    ws.freeze_panes(1, 0)

# -------- Main --------
def main():
    # Load SLA codes (& friendly names)
    with open(SLA_CODES_FILE, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    entries = data.get("sla_report_codes", [])
    if not entries:
        raise SystemExit(f"No 'sla_report_codes' found in {SLA_CODES_FILE}")

    with pd.ExcelWriter(OUTPUT_FILE, engine="xlsxwriter") as writer:
        # Pre-create Summary (we fill content after loop)
        writer.book.add_worksheet("Summary")

        summary_rows = []

        for entry in entries:
            code = entry.get("code")
            name = (entry.get("name") or code or "").strip()
            if not code:
                continue

            # Pull all data for this group
            df_full, problem_details = build_dataset_for_code(code)

            # Summary metrics (ALL devices for this group)
            total_devices = len(df_full)
            enabled_count = int((df_full["Enabled"] == "Yes").sum()) if not df_full.empty else 0
            enabled_avail = df_full.loc[df_full["Enabled"] == "Yes", "Availability %"] if not df_full.empty else pd.Series(dtype=float)
            avg_enabled_avail = round(float(enabled_avail.mean()), 2) if not enabled_avail.empty else 0.0
            problems_total = int(df_full["Problems Raised"].sum()) if not df_full.empty else 0
            downtime_total_min = int(df_full["Total Downtime (min)"].sum()) if not df_full.empty else 0

            # Add to summary (always list the group even if it has no problems)
            summary_rows.append([name, avg_enabled_avail])

            # Build export (only hosts with incidents)
            if not df_full.empty:
                df_export = df_full[df_full["Problems Raised"] > 0].copy()
                if "Enabled" in df_export.columns:
                    df_export.drop(columns=["Enabled"], inplace=True)
            else:
                df_export = df_full

            # If no problems for the group, skip sheet creation
            if df_export.empty:
                continue

            summary = {
                "total_devices": total_devices,
                "enabled_devices": enabled_count,
                "avg_enabled_availability": avg_enabled_avail,
                "problems_total": problems_total,
                "downtime_total_min": downtime_total_min,
            }

            # Ensure sheet names are Excel-safe
            safe_title = sanitize_sheet_name(name or code)
            write_sheet(df_export, problem_details, writer, summary, sheet_title=safe_title)

        # Write the Summary sheet content last
        write_summary_sheet(writer, summary_rows)

    print(f"Excel report written to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
