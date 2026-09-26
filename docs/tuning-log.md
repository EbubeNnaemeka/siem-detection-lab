# Detection Tuning Log

Each rule starts with a hypothesis about where its noise will come from. Run the rule against a few days of normal lab activity, record what actually fired, adjust, and log each iteration here.

## brute-force-auth.spl
- **Starting threshold:** 5+ failures in 5 minutes.
- **Expected noise:** RDP clients retrying after network blips; service accounts with stale passwords.
- **Observed false positives per day:** _fill in_
- **Change made:** _fill in_

## lateral-movement-psexec.spl
- **Starting logic:** `ServiceName="PSEXESVC"` OR `ImagePath="*psexesvc*"`, joined against admin share access (5140).
- **Why both conditions:** matching on the service name alone misses renamed PsExec binaries.
- **Expected noise:** routine service installs and endpoint-management tools.
- **Observed false positives per day:** _fill in_
- **Change made:** _fill in_

## powershell-encoded-command.spl
- **Starting logic:** any `-EncodedCommand`, `-enc`, or `-nop -w hidden` in the command line.
- **Expected noise:** deployment tools (SCCM/Intune) that pass Base64-encoded scripts.
- **Planned mitigation:** triage on `ParentImage` before escalating. Office apps as the parent point to a macro payload; a known deployment tool as the parent is likely benign.
- **Observed false positives per day:** _fill in_
- **Change made:** _fill in_
