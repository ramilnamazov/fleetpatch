# FleetPatch

A single-file Windows GUI tool for remotely detecting and replacing Java executables across a fleet of workstations — without touching each machine manually.

Built with Python + tkinter. No server. No agent. Runs from your admin workstation over PsExec and UNC admin shares.

---

## What it does

1. **Discovers** — scans remote hosts for `java.exe` / `javaw.exe` and reads their version, family (8, 11, 17, 21…), and file path
2. **Plans** — matches discovered files against rules you define, deciding what needs replacing and what can be skipped
3. **Executes** — kills the process if running, takes ownership, clears file attributes, backs up the old file, then copies the new one directly over the admin share
4. **Verifies** — reads the replaced file back from the remote host and confirms the SHA256 hash matches what was deployed

---

## Requirements

| Requirement | Notes |
|---|---|
| Python 3.10+ | With tkinter (standard on Windows) |
| PsExec | From Sysinternals — place anywhere, configure path in the app |
| Admin share access | `\\HOST\C$` must be reachable from your workstation |
| Remote PowerShell | PS 2.0+ on target machines (no WinRM needed) |
| `openpyxl` (optional) | Only needed for Excel inventory export — `pip install openpyxl` |

---

## How to run

```
python fleetpatch.py
```

That's it. Single file, no install, no dependencies beyond standard library (openpyxl optional).

---

## Tabs walkthrough

### 1 — Targets
Define which hosts and drive paths to scan. One host per line, or import a text/CSV file. Supports individual hostnames, IP addresses.

Example:
```
WORKSTATION-01  C:\Program Files\Java  C:\Program Files (x86)\Java
WORKSTATION-02  C:\Tools
```

### 2 — Inventory / Discovery
Click **Run Discovery** to scan all target hosts. FleetPatch connects via PsExec and searches each configured path for the filenames you specify (default: `java.exe`, `javaw.exe`).

Results show:
- Host, full path, file version, Java family (8/11/17/21…)
- Status: FOUND, OFFLINE, BASE_NOT_FOUND, ERROR

Click **Export Excel** to get a multi-sheet `.xlsx` report — one sheet per Java family, sorted with `javaw.exe` before `java.exe`.

### 3 — Rules
Define what to replace and with what. Each rule specifies:

| Field | Description |
|---|---|
| `filename` | Target filename — `java.exe` or `javaw.exe` |
| `match_family` | Only apply this rule to this Java family (e.g. `17`) |
| `source_path` | Path to the replacement binary on your machine |
| `replace_when` | `if_older`, `always`, or `never` |
| `enforce_family_lock` | Block replacement if source binary family doesn't match declared family |
| `backup` | Create a timestamped zip backup before replacing |
| `process_handling` | `kill` (terminate if running), `block` (abort if running), `ignore` |
| `verify_hash` | Confirm SHA256 after replacement |

Rules are stored as `rules.json` — you can edit directly or use the GUI.

### 4 — Plan
Click **Build Plan** to see what will happen before executing. Each row shows:

- `OK` — will be replaced
- `SKIP` — already up to date or no rule matched
- `BLOCKED` — rule is misconfigured (e.g. wrong source binary family), or process is running with `block` mode
- `OFFLINE` — host was unreachable during discovery

Review the plan before executing. SKIP and BLOCKED rows are never touched.

### 5 — Audit (Results)
After execution, every action is recorded here with:
- Result: SUCCESS / ERROR / OFFLINE / BLOCKED / SKIP
- Version delta (e.g. `1.8.0.301 → 17.0.19`)
- Backup path
- Verify status (after clicking Verify All)

Color coded: green = success, red = error/offline, amber = blocked, grey = skip.

Click **Verify All** after execution to re-read each replaced file from the remote host via UNC and confirm the hash matches what was deployed.

---

## Use case scenarios

### Scenario 1 — Standardise Java 8 to a secure patch level
Your fleet has a mix of old Java 8 builds (8.0.201, 8.0.291, etc.) and you need everything on 8.0.492.

1. Add a rule: `filename=java.exe`, `match_family=8`, `source_path=C:\Packages\zulu8.94\bin\java.exe`, `replace_when=if_older`
2. Run Discovery — inventory shows all your Java 8 installs with their current versions
3. Build Plan — rows marked OK are older than 8.0.492, SKIP are already up to date
4. Execute — FleetPatch kills any running java processes, backs up the old file, copies the new one
5. Verify All — confirms every replaced file matches the expected hash

### Scenario 2 — Replace Java 11 with Java 17 on a specific set of hosts
You're migrating an application from Java 11 to 17. You need to replace `java.exe` AND `javaw.exe`.

1. Create two rules — one for `java.exe` matching family `11`, source pointing to your Java 17 binary; one for `javaw.exe` same
2. Set `replace_when=always` since you're changing family, not just patching
3. Keep `enforce_family_lock=false` for these rules (you intentionally want to change family)
4. Run Discovery → Build Plan → Execute

### Scenario 3 — Emergency CVE patch across 500 workstations
A critical CVE drops. You need to patch Java 17 on every machine before end of day.

1. Download the patched Zulu/Corretto/Temurin build
2. Update the `source_path` in your existing Java 17 rule, update `source_file_version`
3. Run Discovery with broad base paths
4. Build Plan — only machines with older builds show as OK
5. Set thread count to 20, execute
6. Export Audit CSV / Excel for compliance evidence

### Scenario 4 — Locked file (Java running inside a service or application)
Some machines run Java inside a Windows service that starts at boot.

- Set `process_handling=kill` on the rule — FleetPatch will find the process by its executable path, kill it, wait up to 15 seconds for it to exit, then replace the file
- The service will restart on next boot with the new binary
- If you don't want to kill: set `process_handling=block` — those hosts will show as BLOCKED in the plan so you can handle them separately

### Scenario 5 — Audit what's deployed without replacing anything
Just want to know what Java versions exist across your fleet?

1. Run Discovery
2. Click **Export Excel** — get a workbook with one sheet per Java family
3. Each sheet is sorted with `javaw.exe` first, then `java.exe`, within each host group

No rules needed, no execution required.

---

## Execution flow (what happens when you click Execute)

For each OK plan item, FleetPatch runs these steps:

```
1. Ping check         — skip if host unreachable
2. TCP 445 check      — verify SMB/admin share is accessible before attempting copy
3. PsExec PREPARE     — runs on the remote machine:
                         • Find and kill the process (if process_handling=kill)
                         • takeown + icacls to grant Administrators full control
                         • attrib -r -s -h to clear ReadOnly/System/Hidden flags
                         • Zip backup of original file (if backup=true)
                         • Record before-version and before-hash
4. UNC COPY           — Python copies source → \\HOST\C$\...\java.exe.fleetpatch_tmp
                         then os.replace() renames it atomically to the target name
                         3 attempts with 2s delay between each
5. PsExec VERIFY      — runs on the remote machine:
                         • Reads after-version and after-hash
                         • SHA256 comparison if verify_hash=true
```

All PowerShell scripts use .NET methods directly — no PS cmdlet version dependencies.

---

## Backup

If backup is enabled on a rule, the original file is zipped to:
```
C:\ProgramData\FleetPatch\Backups\<timestamp>__<filename>.zip
```
on the **remote machine** before replacement. Timestamped so multiple runs don't overwrite each other.

---

## Configuration files

| File | Purpose |
|---|---|
| `rules.json` | Replacement rules — edit in GUI or directly |
| `targets.txt` | Host list — one host per line, or host + paths |

---

## Troubleshooting

| Problem | Likely cause |
|---|---|
| OFFLINE in plan | Host unreachable via ping |
| ERROR: TCP 445 not reachable | Firewall blocking SMB — admin share not accessible |
| ERROR: Target not found | File path doesn't exist on remote host |
| BLOCKED: Family mismatch | Rule's `match_family` doesn't match the source binary — fix `source_path` in the rule |
| BLOCKED: Running process | Process running with `process_handling=block` — change to `kill` or stop manually |
| UNREADABLE in Verify | Admin share not accessible after execution, or file was moved |
| Copy failed after 3 attempts | File still locked, AV holding it, or permissions not fully applied |
