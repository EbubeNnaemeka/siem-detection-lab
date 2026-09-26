# Setup Walkthrough

## 1. Splunk server
1. Register a free account at splunk.com (use a non-personal-looking email if signup rejects Gmail/Yahoo).
2. Download **Splunk Enterprise** for your OS and install.
3. Register for a **Developer license** (10GB/day, free) under Settings > Licensing if the trial expires.
4. Create a dedicated index: `Settings > Indexes > New Index` → name it `winlogs`.

## 2. Add-ons (install on the Splunk server, via Splunkbase)
- Splunk Add-on for Windows
- Splunk Add-on for Sysmon

Without these, Windows XML events won't parse into usable fields (`EventCode`, `Account_Name`, `Image`, etc.) — you'll be stuck grepping raw XML.

## 3. Log source VM
1. Install **Sysmon** using the config in [`../sysmon-config.xml`](../sysmon-config.xml):
   ```
   sysmon64.exe -accepteula -i sysmon-config.xml
   ```
2. Set Windows Event Log forwarding to render as XML (required for the Windows Add-on to parse fields correctly):
   ```
   reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding" /v renderXml /t REG_DWORD /d 1
   ```
3. Install the **Splunk Universal Forwarder**, point it at the Splunk server (port 9997), and configure it to monitor:
   - `Security` event log
   - `Microsoft-Windows-Sysmon/Operational` event log

## 4. Verify ingestion
In Splunk Search: `index=winlogs | stats count by EventCode` — you should see 4624/4625 (logon events) and Sysmon Event ID 1 (process creation) within a few minutes of activity on the log source.
