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
        "auth": None
    }
    r = requests.post(ZABBIX_API_URL, json=payload, headers=headers, verify=False, timeout=10)
    r.raise_for_status()
    return r.json()['result']

# Get hosts with the right tag
hosts = zabbix_api('host.get', {
    "output": ["hostid", "name"],
    "selectTags": "extend",
    "tags": [{"tag": TAG_KEY, "value": TAG_VALUE}]
})

hostids = [h["hostid"] for h in hosts]
hostmap = {h["hostid"]: h["name"] for h in hosts}

now = int(datetime.datetime.now().timestamp())
start = int((datetime.datetime.now() - datetime.timedelta(days=DAYS)).timestamp())

results = []
for hostid in hostids:
    # Step 1: Get ICMP triggers for this host
    triggers = zabbix_api('trigger.get', {
        "hostids": [hostid],
        "output": ["triggerid", "description"],
        "search": {"description": "Unavailable by ICMP ping"},
        "selectItems": ["itemid", "name", "key_"]
    })
    # If you have custom descriptions, adjust the search value above

    icmp_trigger_ids = [t["triggerid"] for t in triggers]
    if not icmp_trigger_ids:
        results.append({
            "Hostname": hostmap[hostid],
            "Availability %": 0.0,
            "Problems Raised": 0,
            "Total Downtime (min)": 0,
        })
        continue

    # Step 2: For each ICMP trigger, get all resolved problem events
    problem_count = 0
    downtime_total = 0
    for triggerid in icmp_trigger_ids:
        # Find problem events for this trigger
        events = zabbix_api('event.get', {
            "output": ["eventid", "clock", "r_eventid", "value"],
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
                # Fetch resolved event time
                resolved_event = zabbix_api('event.get', {
                    "output": ["eventid", "clock"],
                    "eventids": [ev['r_eventid']]
                })
                if resolved_event:
                    down_seconds = int(resolved_event[0]['clock']) - int(ev['clock'])
                    downtime_total += down_seconds
                    problem_count += 1

    # Step 3: Calculate Availability %
    # Get ICMP item for this host (first match)
    icmp_items = zabbix_api('item.get', {
        "output": ["itemid", "name", "hostid", "key_"],
        "hostids": [hostid],
        "search": {"key_": "icmpping"},
        "limit": 1
    })
    availability = 0.0
    if icmp_items:
        itemid = icmp_items[0]["itemid"]
        # Try uint history (0) first
        history = zabbix_api('history.get', {
            "output": "extend",
            "history": 0,
            "itemids": [itemid],
            "time_from": start,
            "time_till": now,
            "limit": 100000
        })
        values = [float(h['value']) for h in history]
        # If empty, try float history (3)
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
    })

df = pd.DataFrame(results)
df.to_csv(OUTPUT_FILE, index=False)
print(f"Report written to {OUTPUT_FILE}")
