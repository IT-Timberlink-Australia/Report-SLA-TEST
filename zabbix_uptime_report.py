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

SEVERITY_MAP = {0: "Not classified", 1: "Information", 2: "Warning", 3: "Average", 4: "High", 5: "Disaster"}

# -------- Utilities --------
def fmt_time(ts: int) -> str:
    try:
        return datetime.datetime.fromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts)

def fmt_duration(seconds: int) -> str:
    seconds = int(max(0, seconds))
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
    """Total overlap in seconds between union of A and union of B (both lists of (s,e))."""
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
    NOTE: This treats maintenance 'active_since'..'active_till' as active range.
    For recurring/timeperiod schedules, Zabbix stores a wide active range; this code
    conservatively clips by active_since/active_till. If you need full recurrence expansion,
    we can add it later.
    """
    maints = zabbix_api('maintenance.get', {
        "output": ["maintenanceid", "name", "active_since", "active_till"],
        "selectHosts": ["hostid"],
        "hostids": [hostid]
    })
    windows = []
    for m in maints:
        ms = int(m.get("active_since", 0))
        me = int(m.get("active_till", 0))
        if me == 0:  # guard; treat 0 as no end (unlikely), cap at report end
            me = end
        clipped = clip_interval(ms, me, start, end)
        if clipped:
            windows.append(clipped)
    return windows

def build_dataset_for_code(tag_value: str, start: int, now: int, window_seconds: int):
    """
    Returns:
      df (DataFrame): columns [Hostname, Availability %, Problems Raised, Total Downtime (min), Enabled]
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
    host_enabled = {h["hostid"]: (str(h.get("status", "0")) == "0") for h in hosts}  # 0 = enabled, 1 = disabled

    results = []
    problem_details = []

    for hostid in hostids:
        # -------- Collect problem intervals (include OPEN problems for availability) --------
        triggers = zabbix_api('trigger.get', {
            "hostids": [hostid],
            "output": ["triggerid", "description", "priority"],
            "search": {"description": "Unavailable by ICMP ping"},
            "selectItems": ["itemid", "name", "key_"]
        })
        trig_map = {t["triggerid"]: t for t in triggers}
        trig_ids = [t["triggerid"] for t in triggers if t.get("triggerid")]

        problem_intervals = []  # for availability (include unresolved)
        problem_count_resolved = 0
        downtime_total_resolved = 0

        for trig_id in trig_ids:
            # Get PROBLEM events in window
            events = zabbix_api('event.get', {
                "output": ["eventid", "clock", "r_eventid", "value"],
                "select_acknowledges": ["clock", "message", "userid", "username", "name", "surname"],
                "source": 0,  # triggers
                "object": 0,  # triggers
                "objectids": [trig_id],
                "time_from": start,
                "time_till": now,
                "value": 1,   # PROBLEM
                "sortfield": ["clock"],
                "sortorder": "ASC"
            })
            for ev in events:
                ev_start = int(ev['clock'])
                r_evid = ev.get('r_eventid', '0')
                if r_evid and str(r_evid) != "0":
                    # resolved
                    resolved_event = zabbix_api('event.get', {"output": ["eventid", "clock"], "eventids": [r_evid]})
                    if resolved_event:
                        ev_end = int(resolved_event[0]['clock'])
                    else:
                        ev_end = now
                else:
                    # unresolved -> treat as open to now
                    ev_end = now

                # clip interval to report window
                clipped = clip_interval(ev_start, ev_end, start, now)
                if not clipped:
                    continue
                cs, ce = clipped
                problem_intervals.append((cs, ce))

                # Build details only for resolved ones (your existing convention)
                if r_evid and str(r_evid) != "0":
                    down_seconds = ce - cs
                    if down_seconds > 0:
                        problem_count_resolved += 1
                        downtime_total_resolved += down_seconds
                        trig = trig_map.get(trig_id, {})
                        sev = SEVERITY_MAP.get(int(trig.get("priority", 0)), str(trig.get("priority", 0)))

                        # ack info (compact notes)
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
                            "Duration": fmt_duration(down_seconds),
                            "Problem": trig.get("description", "Unavailable by ICMP ping"),
                            "Alert Time": fmt_time(cs),
                            "Acknowledged time": ack_time,
                            "Recovery time": fmt_time(ce),
                            "Notes": ack_notes,
                        })

        # -------- Maintenance exclusion --------
        maint_windows = get_maintenance_windows_for_host(hostid, start, now)  # list[(s,e)]
        maint_overlap = intervals_overlap_seconds(problem_intervals, maint_windows) if maint_windows else 0
        total_problem_seconds = sum(e - s for (s, e) in problem_intervals)
        adjusted_downtime = max(0, total_problem_seconds - maint_overlap)

        # -------- SLA availability --------
        availability = 100.00 * (1.0 - (adjusted_downtime / max(1, window_seconds)))

        results.append({
            "Hostname": hostmap[hostid],
            "Availability %": round(availability, 3),
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
    sheet_name = sanitize_sheet_name(sheet_title)
    df.to_excel(writer, sheet_name=sheet_name, startrow=10, index=False)

    workbook  = writer.book
    worksheet = writer.sheets[sheet_name]

    h1   = workbook.add_format({"bold": True, "font_size": 16})
    bold = workbook.add_format({"bold": True})
    pct2 = workbook.add_format({"num_format": "0.00%"})  # percentage format
    int_fmt = workbook.add_format({"num_format": "0"})
    pct_big = workbook.add_format({
    "bold": True,
    "font_size": 16,
    "align": "center",
    "num_format": "0.00%"
})

    # Headers & summary
    worksheet.write("A1", f"SLA Availability Report — {sheet_title}", h1)
    worksheet.write("A3", f"Time Frame: last {DAYS} days")

    worksheet.write("A5", f"Report Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", bold)

    worksheet.write("B6", "Enabled devices", bold)
    worksheet.write_number("C6", summary["enabled_devices"], int_fmt)

    worksheet.write("B7", "Total devices", bold)
    worksheet.write_number("C7", summary["total_devices"], int_fmt)

    # >>> changed block <<<
    worksheet.write("E1", "SLA - Availability", h1)     # bigger + bold
    worksheet.write_number("E2", summary["avg_enabled_availability"]/100.0, pct_big)
    # divide by 100 because we store it as 99.85 not 0.9985
    # <<<<<<<<<<<<<<<<<<<<<<

    worksheet.write("B4", "Total problems (all)", bold)
    worksheet.write_number("C4", summary["problems_total"], int_fmt)

    worksheet.write("B5", "Total downtime (min, all)", bold)
    worksheet.write_number("C5", summary["downtime_total_min"], int_fmt)

    worksheet.write("A10", "Devices with < 100% Uptime", bold)

    # Problem details: leave 5 blank rows after data table
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
    sheet_name = "Summary"
    df_sum = pd.DataFrame(rows, columns=["Group", "SLA - Availability"])
    df_sum.sort_values(by="Group", inplace=True, kind="stable")
    df_sum.reset_index(drop=True, inplace=True)
    df_sum.to_excel(writer, sheet_name=sheet_name, startrow=0, index=False)

    workbook = writer.book
    ws = writer.sheets[sheet_name]

    h1 = workbook.add_format({"bold": True, "font_size": 16})
    pct2 = workbook.add_format({"num_format": "0.00"})
    ws.write("A1", "SLA Availability Summary", h1)

    max_w0 = max([len("Group")] + [len(str(x)) for x in df_sum["Group"].astype(str).tolist()]) if not df_sum.empty else len("Group")
    ws.set_column(0, 0, min(50, max(15, int(max_w0 * 1.1))))
    ws.set_column(1, 1, 22, pct2)
    ws.freeze_panes(1, 0)

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
        writer.book.add_worksheet("Summary")
        summary_rows = []

        for entry in entries:
            code = entry.get("code")
            name = (entry.get("name") or code or "").strip()
            if not code:
                continue

            # Build all data for this SLA code
            df_full, problem_details = build_dataset_for_code(code, start, now, window_seconds)

            # Summary metrics (ALL devices for this group)
            total_devices = len(df_full)
            enabled_count = int((df_full["Enabled"] == "Yes").sum()) if not df_full.empty else 0
            enabled_avail = df_full.loc[df_full["Enabled"] == "Yes", "Availability %"] if not df_full.empty else pd.Series(dtype=float)
            avg_enabled_avail = round(float(enabled_avail.mean()), 3) if not enabled_avail.empty else 0.0
            problems_total = int(df_full["Problems Raised"].sum()) if not df_full.empty else 0
            downtime_total_min = int(df_full["Total Downtime (min)"].sum()) if not df_full.empty else 0

            summary_rows.append([name, avg_enabled_avail])

            # Export only hosts with incidents in the table
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

        write_summary_sheet(writer, summary_rows)

    print(f"Excel report written to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
