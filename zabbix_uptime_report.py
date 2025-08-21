
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
        return pd.DataFrame(columns=["Hostname", "Availability %", "Problems Raised", "Total Downtime (min)", "Enabled"])

    hostids = [h["hostid"] for h in hosts]
    hostmap = {h["hostid"]: h["name"] for h in hosts}
    host_enabled = {h["hostid"]: (str(h.get("status", "0")) == "0") for h in hosts}  # 0 = enabled, 1 = disabled

    now = epoch_now()
    start = epoch_days_ago(DAYS)

    results = []
    for hostid in hostids:
        # Step 1: Get ICMP triggers for this host
        triggers = zabbix_api('trigger.get', {
            "hostids": [hostid],
            "output": ["triggerid", "description"],
            "search": {"description": "Unavailable by ICMP ping"},
            "selectItems": ["itemid", "name", "key_"]
        })

        icmp_trigger_ids = [t["triggerid"] for t in triggers if t.get("triggerid")]
        problem_count = 0
        downtime_total = 0

        # Step 2: For each ICMP trigger, get all resolved problem events
        for triggerid in icmp_trigger_ids:
            events = zabbix_api('event.get', {
                "output": ["eventid", "clock", "r_eventid", "value"],
                "source": 0,
                "object": 0,
                "objectids": [triggerid],
                "time_from": start,
                "time_till": now,
                "value": 1,
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
                        down_seconds = int(resolved_event[0]['clock']) - int(ev['clock'])
                        if down_seconds > 0:
                            downtime_total += down_seconds
                            problem_count += 1

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
    return df

def write_excel_with_summary(df: pd.DataFrame, path: str, summary: dict):
    with pd.ExcelWriter(path, engine="xlsxwriter") as writer:
        sheet_name = "Report"
        df.to_excel(writer, sheet_name=sheet_name, startrow=10, index=False)

        workbook  = writer.book
        worksheet = writer.sheets[sheet_name]

        h1 = workbook.add_format({"bold": True, "font_size": 14})
        bold = workbook.add_format({"bold": True})
        pct2 = workbook.add_format({"num_format": "0.00"})
        int_fmt = workbook.add_format({"num_format": "0"})
        normal = workbook.add_format({})

        worksheet.write("A1", f"Zabbix Availability Report (Tag {TAG_KEY}={TAG_VALUE})", h1)
        worksheet.write("A2", f"Window: last {DAYS} days", normal)

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

        for col_idx, col in enumerate(df.columns.tolist()):
            width = max(12, min(50, int(max([len(str(col))] + [len(str(v)) for v in df[col].astype(str).tolist()]) * 1.1)))
            worksheet.set_column(col_idx, col_idx, width)

        worksheet.freeze_panes(11, 0)

    return {"summary": summary, "output_file": path}

def main():
    df_full = build_dataset()

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

    if not df_full.empty:
        df_export = df_full[~((df_full["Enabled"] == "No") & (df_full["Problems Raised"] == 0))].copy()
        if "Enabled" in df_export.columns:
            df_export.drop(columns=["Enabled"], inplace=True)
    else:
        df_export = df_full

    result = write_excel_with_summary(df_export, OUTPUT_FILE, summary)
    print(f"Excel report written to {result['output_file']}")
    print(f"Summary: {result['summary']}")

if __name__ == "__main__":
    main()
