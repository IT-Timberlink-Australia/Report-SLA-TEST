import os
import re
import requests
import pandas as pd
import urllib3
import yaml
from datetime import datetime
import datetime as dt  # alias for epoch math

# Silence TLS warnings due to verify=False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# -------- Environment --------
ZABBIX_API_URL = os.environ.get('ZABBIX_API_URL')
ZABBIX_API_TOKEN = os.environ.get('ZABBIX_API_TOKEN')
TAG_KEY = os.environ.get('TAG_KEY', 'device')  # e.g. "device" or "sla_report_code"
DAYS = int(os.environ.get('DAYS', '30'))
OUTPUT_FILE = os.environ.get('REPORT_OUTPUT', '/tmp/zabbix_sla_report.xlsx')
SLA_CODES_FILE = os.environ.get('SLA_CODES_FILE', '/runner/artifacts/sla_codes.yml')

SEVERITY_MAP = {0: "Not classified", 1: "Information", 2: "Warning", 3: "Average", 4: "High", 5: "Disaster"}

# -------- Utilities --------
def fmt_time(ts: int) -> str:
    try:
        return dt.datetime.fromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts)

def fmt_duration(seconds: int) -> str:
    seconds = int(max(0, seconds))
    h = seconds // 3600
    m = (seconds % 3600) // 60
    s = seconds % 60
    return f"{h:d}:{m:02d}:{s:02d}"

def epoch_now() -> int:
    return int(dt.datetime.now().timestamp())

def epoch_days_ago(days: int) -> int:
    return int((dt.datetime.now() - dt.timedelta(days=days)).timestamp())

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
    # Excel worksheet name cannot contain : \ / ? * [ ] and must be <= 31 chars
    name = re.sub(r'[:\\/?*\[\]]', '_', name)
    return name[:31]

# ---- interval helpers ----
def clip_interval(a_start, a_end, start, end):
    """Clip [a_start, a_end] to [start, end]; return (s,e) or None if no overlap."""
    s = max(a_start, start)
    e = min(a_end, end)
    if e > s:
        return (s, e)
    return None

def intervals_overlap_seconds(intervals_a, intervals_b):
    """Total overlap in seconds between union of A and union of B (lists of (s,e))."""
    total = 0
    for (as_, ae) in intervals_a:
        for (bs, be) in intervals_b:
            s = max(as_, bs)
            e = min(ae, be)
            if e > s:
                total += (e - s)
    return total

# -------- Data builders --------
def get_maintenance_windows_for_host(hostid: str, start: int, end: int):
    """
    Returns list of concrete maintenance intervals (start,end) intersected with [start,end].
    For recurring maintenances with long active ranges, this clips by active_since/active_till.
    """
    maints = zabbix_api('maintenance.get', {
        "output": ["maintenanceid", "name", "active_since", "active_till"],
        "selectHosts": ["hostid"],
        "hostids": [hostid]
    })
    windows = []
    for m in maints:
        ms = int(m.get("active_since", 0))
        me = int(m.get("active_till", 0)) or end
        clipped = clip_interval(ms, me, start, end)
        if clipped:
            windows.append(clipped)
    return windows

def build_dataset_for_code(tag_value: str, start: int, now: int, window_seconds: int):
    """
    Returns:
      df (DataFrame): [Hostname, Availability %, Problems Raised, Total Downtime (min), Enabled]
      problem_details (list[dict]): for the "Problem details" table (resolved only)
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
    host_enabled = {h["hostid"]:(str(h.get("status","0"))=="0") for h in hosts}  # 0=enabled, 1=disabled

    results = []
    problem_details = []

    for hostid in hostids:
        # Collect problem intervals (include OPEN problems for availability)
        triggers = zabbix_api('trigger.get', {
            "hostids": [hostid],
            "output": ["triggerid", "description", "priority"],
            "search": {"description": "Unavailable by ICMP ping"},
            "selectItems": ["itemid", "name", "key_"]
        })
        trig_map = {t["triggerid"]: t for t in triggers}
        trig_ids = [t["triggerid"] for t in triggers if t.get("triggerid")]

        problem_intervals = []           # for availability (include unresolved)
        problem_count_resolved = 0       # for table
        downtime_total_resolved = 0      # for table

        for trig_id in trig_ids:
            events = zabbix_api('event.get', {
                "output": ["eventid", "clock", "r_eventid", "value"],
                "select_acknowledges": ["clock", "message", "userid", "username", "name", "surname"],
                "source": 0, "object": 0,
                "objectids": [trig_id],
                "time_from": start, "time_till": now,
                "value": 1,
                "sortfield": ["clock"], "sortorder": "ASC"
            })
            for ev in events:
                ev_start = int(ev['clock'])
                r_evid = ev.get('r_eventid', '0')
                if r_evid and str(r_evid) != "0":
                    resolved_event = zabbix_api('event.get', {"output": ["eventid", "clock"], "eventids": [r_evid]})
                    ev_end = int(resolved_event[0]['clock']) if resolved_event else now
                else:
                    ev_end = now

                clipped = clip_interval(ev_start, ev_end, start, now)
                if not clipped:
                    continue
                cs, ce = clipped
                problem_intervals.append((cs, ce))

                # Details for resolved only
                if r_evid and str(r_evid) != "0":
                    down_s = ce - cs
                    if down_s > 0:
                        problem_count_resolved += 1
                        downtime_total_resolved += down_s
                        trig = trig_map.get(trig_id, {})
                        sev = SEVERITY_MAP.get(int(trig.get("priority", 0)), str(trig.get("priority", 0)))

                        # ack info
                        ack_time = ""
                        ack_notes = ""
                        acks = ev.get("acknowledges", []) or []
                        if acks:
                            acks_sorted = sorted(acks, key=lambda a: int(a.get("clock", 0)))
                            ack_time = fmt_time(acks_sorted[0].get("clock"))
                            parts = []
                            for a in acks_sorted:
                                ts = fmt_time(a.get("clock"))
                                uname2 = (a.get("username") or "")[:2]
                                msg = (a.get("message") or "").strip()
                                parts.append(f"[{ts}] {uname2}: {msg}" if msg else f"[{ts}] {uname2}")
                            ack_notes = " | ".join(parts)

                        problem_details.append({
                            "Host": hostmap[hostid],
                            "Severity": sev,
                            "Status": "RESOLVED",
                            "Duration": fmt_duration(down_s),
                            "Problem": trig.get("description", "Unavailable by ICMP ping"),
                            "Alert Time": fmt_time(cs),
                            "Acknowledged time": ack_time,
                            "Recovery time": fmt_time(ce),
                            "Notes": ack_notes,
                        })

        # Maintenance exclusion
        maint_windows = get_maintenance_windows_for_host(hostid, start, now)
        maint_overlap = intervals_overlap_seconds(problem_intervals, maint_windows) if maint_windows else 0
        total_problem_seconds = sum(e - s for (s, e) in problem_intervals)
        adjusted_downtime = max(0, total_problem_seconds - maint_overlap)

        # SLA availability
        availability = 100.0 * (1.0 - (adjusted_downtime / max(1, window_seconds)))

        results.append({
            "Hostname": hostmap[hostid],
            "Availability %": round(availability, 2),
            "Problems Raised": problem_count_resolved,
            "Total Downtime (min)": round(downtime_total_resolved / 60),
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
    sheet_name = sanitize_sheet_name(sheet_title)
    df.to_excel(writer, sheet_name=sheet_name, startrow=10, index=False)

    workbook  = writer.book
    worksheet = writer.sheets[sheet_name]

    h1       = workbook.add_format({"bold": True, "font_size": 16})
    bold     = workbook.add_format({"bold": True})
    pct_big  = workbook.add_format({"bold": True, "font_size": 16, "num_format": "0.00%", "align": "center", "valign": "vcenter"})
    int_fmt  = workbook.add_format({"num_format": "0"})

    # Header block
    worksheet.write("A1", f"SLA Availability Report — {sheet_title}", h1)
    worksheet.write("A3", f"Time Frame: last {DAYS} days")
    worksheet.write("A5", f"Report Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", bold)

    worksheet.write("B6", "Enabled devices", bold)
    worksheet.write_number("C6", summary["enabled_devices"], int_fmt)

    worksheet.write("D6", "Total devices", bold)
    worksheet.write_number("E6", summary["total_devices"], int_fmt)

    # SLA headline
    worksheet.write("D2", "SLA - Availability", h1)
    worksheet.write_number("E2", summary["avg_enabled_availability"] / 100.0, pct_big)

    worksheet.write("B4", "Total problems (all)", bold)
    worksheet.write_number("C4", summary["problems_total"], int_fmt)

    worksheet.write("B5", "Total downtime (min, all)", bold)
    worksheet.write_number("C5", summary["downtime_total_min"], int_fmt)

    worksheet.write("A10", "Devices with < 100% Uptime", bold)

    # Problem details (5 blank rows after table)
    details_start_row = 10 + 1 + len(df) + 5
    details_cols = [
        "Host", "Severity", "Status", "Duration",
        "Problem", "Alert Time", "Acknowledged time", "Recovery time", "Notes"
    ]
    df_details = pd.DataFrame(problem_details, columns=details_cols)

    for col_idx, col in enumerate(details_cols):
        worksheet.write(details_start_row, col_idx, col, bold)
    for r_idx, row in df_details.iterrows():
        for c_idx, col in enumerate(details_cols):
            worksheet.write(details_start_row + 1 + r_idx, c_idx, row[col])

    # Column widths
    for col_idx, col in enumerate(df.columns.tolist()):
        width = max(12, min(60, int(max([len(str(col))] + [len(str(v)) for v in df[col].astype(str).tolist()]) * 1.1)))
        worksheet.set_column(col_idx, col_idx, width)
    for col_idx, col in enumerate(details_cols):
        col_values = df_details[col].astype(str).tolist() if not df_details.empty else []
        width = max(12, min(80, int(max([len(str(col))] + [len(v) for v in col_values]) * 1.1)))
        worksheet.set_column(col_idx, col_idx, width)

    worksheet.freeze_panes(11, 0)

def write_summary_sheet(writer: pd.ExcelWriter, rows: list):
    """
    rows: list of dicts:
      { 'name': str, 'availability_frac': float (0..1), 'enabled_count': int }
    Layout:
      A1: heading
      A3: Report Date
      A4: Time Frame
      Table headers on row 5; data from row 6
    """
    sheet_name = "Summary"
    workbook = writer.book
    ws = workbook.add_worksheet(sheet_name)

    # Formats
    h1   = workbook.add_format({"bold": True, "font_size": 16})
    hdr  = workbook.add_format({"bold": True, "bg_color": "#D9D9D9"})
    pct  = workbook.add_format({"num_format": "0.00%", "align": "center"})
    ctr  = workbook.add_format({"align": "center"})

    # Heading + meta
    ws.write("A1", "SLA Availability Summary", h1)
    ws.write("A3", f"Report Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    ws.write("A4", f"Time Frame: last {DAYS} days")

    # Headers at row 5 (0-indexed row 4)
    ws.write("A5", "SLA Group", hdr)
    ws.write("B5", "SLA - Availability", hdr)
    ws.write("C5", "Enabled Devices", hdr)

    # Data rows start row 6 (0-indexed row 5)
    r = 5
    # Sort alphabetically by group name; change to availability sort if desired
    for entry in sorted(rows, key=lambda x: x['name']):
        ws.write(r, 0, entry['name'])
        ws.write_number(r, 1, float(entry['availability_frac']), pct)
        ws.write_number(r, 2, int(entry['enabled_count']), ctr)
        r += 1

    # Column widths
    ws.set_column("A:A", 40)
    ws.set_column("B:B", 22, pct)
    ws.set_column("C:C", 18, ctr)

    ws.freeze_panes(6, 0)  # freeze just below header row

# -------- Main --------
def main():
    start = epoch_days_ago(DAYS)
    now = epoch_now()
    window_seconds = max(1, now - start)

    with open(SLA_CODES_FILE, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    entries = data.get("sla_report_codes", [])
    if not entries:
        raise SystemExit(f"No 'sla_report_codes' found in {SLA_CODES_FILE}")

    with pd.ExcelWriter(OUTPUT_FILE, engine="xlsxwriter") as writer:
        # We'll add Summary as a new worksheet with our custom layout
        summary_rows = []

        for entry in entries:
            code = entry.get("code")
            name = (entry.get("name") or code or "").strip()
            if not code:
                continue

            # Build data
            df_full, problem_details = build_dataset_for_code(code, start, now, window_seconds)

            # Summary metrics (ALL devices for this group)
            total_devices = len(df_full)
            enabled_count = int((df_full["Enabled"] == "Yes").sum()) if not df_full.empty else 0
            enabled_avail = df_full.loc[df_full["Enabled"] == "Yes", "Availability %"] if not df_full.empty else pd.Series(dtype=float)
            avg_enabled_avail = round(float(enabled_avail.mean()), 2) if not enabled_avail.empty else 0.0
            problems_total = int(df_full["Problems Raised"].sum()) if not df_full.empty else 0
            downtime_total_min = int(df_full["Total Downtime (min)"].sum()) if not df_full.empty else 0

            # For Summary sheet: store fraction for % formatting and enabled device count
            summary_rows.append({
                "name": name,
                "availability_frac": (avg_enabled_avail / 100.0),
                "enabled_count": enabled_count
            })

            # Export only hosts with incidents
            if not df_full.empty:
                df_export = df_full[df_full["Problems Raised"] > 0].copy()
                if "Enabled" in df_export.columns:
                    df_export.drop(columns=["Enabled"], inplace=True)
            else:
                df_export = df_full

            if df_export.empty:
                continue

            summary = {
                "total_devices": total_devices,
                "enabled_devices": enabled_count,
                "avg_enabled_availability": avg_enabled_avail,
                "problems_total": problems_total,
                "downtime_total_min": downtime_total_min,
            }

            safe_title = sanitize_sheet_name(name or code)
            write_sheet(df_export, problem_details, writer, summary, sheet_title=safe_title)

        # Write the Summary sheet last
        write_summary_sheet(writer, summary_rows)

    print(f"Excel report written to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
