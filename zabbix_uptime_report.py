import os
import requests
import datetime
import pandas as pd

# Environment variables from AWX
ZABBIX_API_URL = os.environ.get('ZABBIX_API_URL')
ZABBIX_API_TOKEN = os.environ.get('ZABBIX_API_TOKEN')
TAG_KEY = 'device'
TAG_VALUE = 'egw.net'
DAYS = 30
OUTPUT_FILE = os.environ.get('REPORT_OUTPUT', '/tmp/egw_net_zabbix_report.csv')

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
        "auth": None  # Token-based auth does not require this
    }
    # Add timeout=10 (10 seconds)
    r = requests.post(ZABBIX_API_URL, json=payload, headers=headers, verify=False, timeout=10)
    r.raise_for_status()
    return r.json()['result']

# Get hosts with tag
hosts = zabbix_api('host.get', {
    "output": ["hostid", "name"],
    "selectTags": "extend",
    "search": {"tags": [{"tag": TAG_KEY, "value": TAG_VALUE}]}
})

hostids = [h["hostid"] for h in hosts]
hostmap = {h["hostid"]: h["name"] for h in hosts}

now = int(datetime.datetime.now().timestamp())
start = int((datetime.datetime.now() - datetime.timedelta(days=DAYS)).timestamp())

# Get ICMP Ping item for each host
items = zabbix_api('item.get', {
    "output": ["itemid", "name", "hostid", "key_"],
    "hostids": hostids,
    "search": {"key_": "icmpping"},
})

# Calculate availability for each host
results = []
for item in items:
    # Fetch history (0=uint, 3=float; icmpping is usually uint)
    history = zabbix_api('history.get', {
        "output": "extend",
        "history": 0,  # 0 = numeric (unsigned)
        "itemids": [item["itemid"]],
        "time_from": start,
        "time_till": now,
        "limit": 100000  # Increase if you have lots of history data points
    })
    values = [float(h['value']) for h in history]
    if values:
        availability = 100.0 * sum(values) / len(values)
    else:
        availability = 0.0

    # Get problems for the host in this period
    problems = zabbix_api('problem.get', {
        "output": "extend",
        "hostids": [item["hostid"]],
        "time_from": start,
        "time_till": now,
    })
    total_downtime = 0
    for p in problems:
        if 'r_eventid' in p and p['r_eventid'] != "0":
            total_downtime += int(p['duration']) // 60  # minutes

    results.append({
        "Hostname": hostmap[item["hostid"]],
        "Availability %": round(availability, 2),
        "Problems Raised": len(problems),
        "Total Downtime (min)": total_downtime,
    })

# Output main table
df = pd.DataFrame(results)
df.to_csv(OUTPUT_FILE, index=False)
print(f"Report written to {OUTPUT_FILE}")
