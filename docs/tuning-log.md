# Detection Tuning Log

## Test setup (2026-09-26)

- Splunk Enterprise 10.4.3 in Docker ([`docker-compose.yml`](../docker-compose.yml))
- Data: [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES), 278 public `.evtx` recordings of real attack techniques, converted with [`scripts/convert_evtx.py`](../scripts/convert_evtx.py) and loaded with [`scripts/load_sample_data.py`](../scripts/load_sample_data.py): **37,364 events**
- Rules run with [`scripts/run_detections.py`](../scripts/run_detections.py)

**Limits of this data.** The dataset is almost entirely attack traffic, so it shows whether a rule *catches* a technique, not how noisy it is in a normal environment. False-positive rates still need measuring against benign lab activity. Field names were mapped to match the Splunk Add-on for Windows (e.g. `TargetUserName` → `Account_Name`, `IpAddress` → `src_ip`) in the loader, not by the add-on itself.

## Results

| Rule | Result | Notes |
|---|---|---|
| powershell-encoded-command | **3 alerts, all malicious** | Includes PowerShell spawned by `w3wp.exe` (IIS) with `-enc`, a web-shell pattern |
| lateral-movement-psexec v1 | **0 alerts — missed everything** | See below |
| lateral-movement-psexec v2 | **8 alerts across 4 hosts** | 7 lateral movement, 1 local privesc (miscategorised) |
| brute-force-auth | 0 alerts (correct) | Dataset has only one 4625 event; rule is untested on a positive case |
| kerberoasting (purple-team repo) | 0 alerts (correct) | Only two 4769 events, both AES (`0x12`); found a format bug, see below |

## lateral-movement-psexec: v1 → v2

**v1** matched `ServiceName="PSEXESVC"` joined with admin-share access. Against the dataset it returned **nothing**, despite several lateral-movement recordings. Looking at the raw events showed why: none of them used the default service name.

- `LM_renamed_psexecsvc_5145`: PsExec with its service binary renamed to `blabla.exe`
- `DE_renamed_psexec_service_sysmon_17_18`: PsExec running under the service name `svchost`
- `LM_REMCOM_5145_TargetHost`: RemCom, an open-source PsExec clone
- `LM_Remote_Service02_7045`: services created remotely that run `cmd.exe`

**v2** drops the tool name and looks for behaviour that renaming can't hide:

| Signal | Event | What it catches |
|---|---|---|
| `admin_exe` | 5145 | An `.exe` written to `ADMIN$`/`C$` — the tool staging its service binary |
| `exec_pipe` | Sysmon 17/18 | Pipes named `<svc>-<host>-<pid>-stdin/stdout/stderr` — PsExec's I/O pattern, kept even when renamed (seen as `\svchost-MSEDGEWIN10-8116-stdin`) |
| `svc_install` | 7045 | A service whose command line is `cmd.exe`, `%COMSPEC%`, PowerShell, etc. |

Result: 8 alerts. 7 are genuine lateral movement. 1 (`WinPwnage`, a `%COMSPEC%` service) is a **local** privilege-escalation tool — malicious, but not lateral movement. Left in deliberately: it's worth an analyst's time, and the triage notes cover it.

All 8 are `medium` because each sample recorded one technique in isolation, so signals never co-occur. In a real intrusion `admin_exe` and `exec_pipe` fire together within seconds, which the rule scores `high`.

Also added `PipeEvent` logging to [`sysmon-config.xml`](../sysmon-config.xml) — without it the `exec_pipe` signal never exists.

## kerberoasting: encryption type format bug

v1 matched `Ticket_Encryption_Type=0x17` as text. The dataset logs this field zero-padded (`0x00000012`), so an RC4 ticket would appear as `0x00000017` and **v1 would miss it**. v2 converts the hex to a number and compares against 23 (RC4-HMAC). Verified with `makeresults`:

| Value | v1 match | v2 match |
|---|---|---|
| `0x17` | yes | yes |
| `0x00000017` | **no** | yes |
| `0x12` (AES) | no | no |
| `0x00000012` (AES) | no | no |

Also excluded computer accounts (`*$`) and `krbtgt`, which are never realistic Kerberoasting targets.

## Still to do

- Measure false positives against a few days of benign activity once the AD lab is running
- Get a positive test case for brute-force-auth (generate repeated failed logons against a lab test account)
