# -*- coding: utf-8 -*-
r"""
FleetPatch — Remote file deployment and patching across Windows hosts.

Major behaviors
---------------
1) Discovery/inventory can run WITHOUT rules. Enter filenames in the Inventory tab.
2) Rules are optional until you want to build a remediation plan.
3) Remote execution uses PsExec + encoded PowerShell.
4) Files are copied directly to their target location via admin share (\\HOST\C$) — no staging.
5) Single-file replacement uses backup, temp copy, SHA256 verification, and rollback attempt.
6) Folder-overlay replacement backs up the detected home folder to ZIP and verifies the matching probe file.
7) No REVIEW status exists — plan items are OK, SKIP, or BLOCKED. BLOCKED items must have their rule or source fixed.

Requirements
------------
- Python 3.10+ on a Windows admin workstation
- PsExec.exe
- Admin rights and admin share access to target computers: \\HOST\C$
"""

from __future__ import annotations

import base64
import csv
import hashlib
import json
import ntpath
import os
import queue
import re
import shutil
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

APP_NAME = "FleetPatch"
REMOTE_ROOT = r"C:\ProgramData\FleetPatch"
REMOTE_BACKUPS = REMOTE_ROOT + r"\Backups"
REMOTE_LOGS = REMOTE_ROOT + r"\Logs"
DEFAULT_BASES = [r"C:\Program Files", r"C:\Program Files (x86)"]
DEFAULT_EXCLUDES = [
    r"C:\Windows",
    r"C:\Windows\WinSxS",
    r"C:\$Recycle.Bin",
    r"C:\System Volume Information",
    r"C:\ProgramData\Microsoft\Windows Defender",
    r"C:\ProgramData\FleetPatch",           # our own backup/log dirs
    r"C:\ProgramData\RemoteFileRemediator", # legacy app name — leftover staging dirs
]
LOG_MAX_LINES = 5_000  # cap on log Text widget lines to prevent unbounded growth
RESULT_PRIORITY = {"ERROR": 0, "OFFLINE": 1, "BLOCKED": 2, "SUCCESS": 3, "SKIP": 4}

# =============================================================================
# Helpers
# =============================================================================

def now_ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def ui_ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def ps_sq(s: str) -> str:
    return (s or "").replace("'", "''")


def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value or "item").strip("_") or "item"


def normalize_win_path(p: str) -> str:
    return (p or "").replace("/", "\\").strip()


def split_filename_list(raw: str) -> List[str]:
    parts = re.split(r"[,;\n\r\t ]+", raw or "")
    cleaned = []
    seen = set()
    for x in parts:
        x = x.strip().strip('"').strip("'")
        if not x:
            continue
        k = x.lower()
        if k not in seen:
            cleaned.append(x)
            seen.add(k)
    return cleaned


def version_to_tuple(v: str) -> Tuple[int, ...]:
    if not v:
        return tuple()
    nums = re.findall(r"\d+", v.replace("_", "."))
    return tuple(int(x) for x in nums[:8]) if nums else tuple()


def compare_versions(a: str, b: str) -> int:
    ta, tb = version_to_tuple(a), version_to_tuple(b)
    if not ta or not tb:
        return 0
    n = max(len(ta), len(tb))
    ta += (0,) * (n - len(ta))
    tb += (0,) * (n - len(tb))
    return -1 if ta < tb else (1 if ta > tb else 0)


def family_major_from_version(version: str, product_version: str, path: str) -> str:
    for v in (version, product_version):
        if v:
            v = v.strip()
            m = re.match(r"^1\.(\d+)\.", v)   # legacy: 1.8.0_292 -> 8
            if m:
                return m.group(1)
            m = re.match(r"^(\d+)[u.]", v)    # 17.0.12... or 8u292 -> 17 or 8
            if m:
                return m.group(1)
            m = re.match(r"^(\d+)$", v)        # bare number
            if m:
                return m.group(1)
    p = (path or "").lower()
    if "jre1.8.0" in p or "jdk1.8.0" in p:
        return "8"
    # Match common Java distribution naming patterns in install paths:
    # jdk-11, jre8, zulu-8, corretto-17, temurin-11, semeru-17, graalvm-ce-java11, etc.
    m = re.search(r"(?:jre|jdk|zulu|corretto|temurin|semeru|graalvm[^\\]*?java)[-_ ]?(\d{1,2})", p)
    return m.group(1) if m else ""


def infer_home_from_file(full_path: str) -> str:
    # ntpath parses Windows paths correctly even if linted/tested on non-Windows.
    p = normalize_win_path(full_path).rstrip("\\")
    parent = ntpath.dirname(p)
    if parent.lower().endswith("\\bin"):
        return ntpath.dirname(parent)
    return parent


def friendly_family(filename: str, family: str, product: str, company: str) -> str:
    """Return a human-readable family label, e.g. 'Java 8', 'Java 11'."""
    fn = (filename or "").lower()
    prod = (product or "").lower()
    comp = (company or "").lower()
    is_java = "java" in fn or "java" in prod or "oracle" in comp or "corretto" in prod or "adoptium" in prod or "temurin" in prod
    if is_java:
        return f"Java {family}" if family else "Java (unknown version)"
    if family:
        # Generic: try to get a short product name prefix
        if product:
            short = product.split()[0] if product.split() else product
            return f"{short} {family}"
        return family
    return product or "Unknown"


def local_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def run_local(cmd: List[str], timeout: int = 300) -> Tuple[int, str, str]:
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, startupinfo=si)
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired:
        return 998, "", f"Timeout after {timeout}s"
    except Exception as e:
        return 997, "", repr(e)


def ping_host(host: str, timeout_ms: int = 1200) -> bool:
    code, _, _ = run_local(["ping", "-n", "1", "-w", str(timeout_ms), host], timeout=6)
    return code == 0


def check_smb(host: str, timeout: float = 3.0) -> bool:
    """Return True if TCP port 445 (SMB/admin share) is reachable on host."""
    import socket
    try:
        with socket.create_connection((host, 445), timeout=timeout):
            return True
    except OSError:
        return False


def parse_json_lines(text: str) -> List[Dict[str, Any]]:
    """Return only lines that parse as JSON objects — skip plain-text PsExec status lines."""
    rows = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            rows.append(json.loads(line))
        except Exception:
            pass
    return rows


def _version_delta(row: "AuditRow") -> str:
    b, a = row.before_version or "", row.after_version or ""
    if b and a:
        return f"{b} → {a}"
    return b or a or "—"

# =============================================================================
# Data models
# =============================================================================

@dataclass
class Target:
    host: str
    bases: List[str] = field(default_factory=lambda: list(DEFAULT_BASES))


@dataclass
class Rule:
    name: str
    enabled: bool = True
    priority: int = 100
    filename: str = "java.exe"
    match_family: str = ""  # blank = any, Java examples: 8, 11, 17
    source_path: str = ""
    source_type: str = "single_file"  # single_file | folder_overlay
    replace_when: str = "if_older"  # if_older | if_different | always | inventory_only
    block_if_unknown_version: bool = True
    enforce_family_lock: bool = True
    backup: bool = True
    verify_hash: bool = True
    process_handling: str = "block"  # block | kill | ignore
    source_file_version: str = ""
    source_product_version: str = ""
    source_sha256: str = ""


@dataclass
class InventoryItem:
    host: str
    base: str
    filename: str
    full_path: str
    file_version: str = ""
    product_version: str = ""
    company: str = ""
    product: str = ""
    family: str = ""
    home: str = ""
    status: str = "FOUND"
    message: str = ""


@dataclass
class PlanItem:
    host: str
    base: str
    filename: str
    target_path: str
    target_version: str
    target_family: str
    rule_name: str
    source_path: str
    source_type: str
    source_version: str
    source_family: str
    status: str
    reason: str
    home: str = ""


@dataclass
class AuditRow:
    timestamp: str
    host: str
    rule_name: str
    filename: str
    target_path: str
    source_path: str
    source_type: str
    result: str
    message: str
    before_version: str = ""
    after_version: str = ""
    before_hash: str = ""
    after_hash: str = ""
    source_hash: str = ""
    backup_path: str = ""
    staged_path: str = ""
    verify_status: str = ""   # "", "VERIFIED", "MISMATCH", "UNREADABLE", "N/A"


def source_probe_file(rule: Rule) -> str:
    r"""Local file used to read source version/hash.

    For folder_overlay, the source path is a folder. We try common layouts:
    <source>\bin\<filename> then <source>\<filename>.
    """
    src = rule.source_path or ""
    if rule.source_type == "single_file":
        return src
    if rule.source_type == "folder_overlay" and src:
        for c in (os.path.join(src, "bin", rule.filename), os.path.join(src, rule.filename)):
            if os.path.isfile(c):
                return c
    return ""


def probe_relative_path(rule: Rule) -> str:
    probe = source_probe_file(rule)
    if not probe or not rule.source_path or rule.source_type != "folder_overlay":
        return ""
    try:
        return os.path.relpath(probe, rule.source_path).replace("/", "\\")
    except Exception:
        return ""

# =============================================================================
# PsExec runner / staging
# =============================================================================

class PsExecRunner:
    def __init__(self, psexec_path: str, timeout_sec: int = 900, run_as_system: bool = True):
        self.psexec_path = psexec_path
        self.timeout_sec = timeout_sec
        self.run_as_system = run_as_system
        self.username = ""
        self.password = ""
        self.elevate = False
        self._lock = threading.Lock()
        self._active: set[subprocess.Popen] = set()

    def validate(self) -> Tuple[bool, str]:
        if not self.psexec_path or not os.path.exists(self.psexec_path):
            return False, f"PsExec not found: {self.psexec_path}"
        return True, "OK"

    def kill_all(self) -> None:
        with self._lock:
            procs = list(self._active)
        for p in procs:
            try:
                p.terminate()
            except Exception:
                pass
        time.sleep(0.5)
        for p in procs:
            try:
                p.kill()
            except Exception:
                pass

    def run_ps(self, host: str, ps_script: str, timeout: Optional[int] = None) -> Tuple[int, str, str]:
        ok, msg = self.validate()
        if not ok:
            return 999, "", msg
        encoded = base64.b64encode(ps_script.encode("utf-16le")).decode("ascii")
        cmd = [self.psexec_path, fr"\\{host}", "-accepteula"]
        if self.username:
            cmd += ["-u", self.username]
            if self.password:
                cmd += ["-p", self.password]
        elif self.run_as_system:
            cmd.append("-s")
        if self.elevate:
            cmd.append("-h")
        cmd += ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded]
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        proc = None
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, startupinfo=si)
            with self._lock:
                self._active.add(proc)
            out, err = proc.communicate(timeout=timeout or self.timeout_sec)
            return proc.returncode or 0, out or "", err or ""
        except subprocess.TimeoutExpired:
            if proc:
                try:
                    proc.kill()
                except Exception:
                    pass
            return 998, "", f"Timeout after {timeout or self.timeout_sec}s"
        except Exception as e:
            return 997, "", repr(e)
        finally:
            if proc:
                with self._lock:
                    self._active.discard(proc)


def admin_share_path(host: str, remote_path: str) -> str:
    rp = normalize_win_path(remote_path)
    if re.match(r"^[A-Za-z]:\\", rp):
        drive = rp[0].upper() + "$"
        rest = rp[3:]
        return fr"\\{host}\{drive}\{rest}"
    raise ValueError(f"Only drive-letter paths are supported for admin share copy: {remote_path}")


def _xcopy_to_unc(source: str, dest_unc: str, is_dir: bool) -> bool:
    """Try xcopy.exe to a UNC destination. Returns True on success."""
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    try:
        if is_dir:
            # /E=include empty dirs, /I=dst is dir, /Y=no prompt, /Q=quiet, /H=hidden files
            cmd = ["xcopy", source, dest_unc, "/E", "/I", "/Y", "/Q", "/H"]
        else:
            # Trailing backslash tells xcopy the destination is a directory
            dst_dir = dest_unc.rstrip("\\") + "\\"
            cmd = ["xcopy", source, dst_dir, "/Y", "/Q"]
        r = subprocess.run(cmd, capture_output=True, timeout=300, startupinfo=si)
        # xcopy returns 0 (nothing copied but no error) or 1 (files copied) on success
        return r.returncode in (0, 1)
    except Exception:
        return False


def copy_any_to_remote(host: str, source_path: str, remote_dest_dir: str, runner: PsExecRunner) -> str:
    """Stage local file/folder to remote host via admin share.

    Tries xcopy.exe first (faster, better retry on large trees); falls back to
    shutil over UNC if xcopy is unavailable or fails.
    """
    source_path = os.path.abspath(source_path)
    if not os.path.exists(source_path):
        raise FileNotFoundError(source_path)
    runner.run_ps(host, f"New-Item -ItemType Directory -Force -LiteralPath '{ps_sq(remote_dest_dir)}' | Out-Null")
    remote_unc_dir = admin_share_path(host, remote_dest_dir)
    os.makedirs(remote_unc_dir, exist_ok=True)
    name = os.path.basename(source_path.rstrip("\\/"))
    remote_unc = os.path.join(remote_unc_dir, name)
    if os.path.isdir(source_path):
        if os.path.exists(remote_unc):
            shutil.rmtree(remote_unc, ignore_errors=True)
        if not _xcopy_to_unc(source_path, remote_unc, is_dir=True):
            # xcopy may have left a partial directory; remove before shutil
            if os.path.exists(remote_unc):
                shutil.rmtree(remote_unc, ignore_errors=True)
            shutil.copytree(source_path, remote_unc)
    else:
        if not _xcopy_to_unc(source_path, remote_unc, is_dir=False):
            shutil.copy2(source_path, remote_unc)
    return normalize_win_path(remote_dest_dir + "\\" + name)



# =============================================================================
# PowerShell builders
# =============================================================================

class PS:
    @staticmethod
    def discover(base: str, filenames: List[str], max_depth: int, excludes: List[str], max_results: int) -> str:
        names = ",".join([f"'{ps_sq(x.strip())}'" for x in filenames if x.strip()])
        exs = ",".join([f"'{ps_sq(x.strip().rstrip('\\'))}'" for x in excludes if x.strip()])
        return f"""
$ErrorActionPreference='SilentlyContinue'
$base='{ps_sq(base)}'
$names=@({names})
$excludes=@({exs})
$maxDepth={int(max_depth)}
$maxResults={int(max_results)}
$count=0
if (!(Test-Path -LiteralPath $base)) {{
  [ordered]@{{kind='error'; code='BASE_NOT_FOUND'; base=$base; message=$base}} | ConvertTo-Json -Compress
  exit 0
}}
function IsExcluded([string]$p) {{
  foreach($e in $excludes) {{ if($e -and $p.StartsWith($e, [System.StringComparison]::OrdinalIgnoreCase)) {{ return $true }} }}
  return $false
}}
function InDepth([string]$full) {{
  if($maxDepth -lt 0) {{ return $true }}
  $rel=$full.Substring($base.Length).TrimStart('\\')
  $depth=if($rel) {{ ($rel -split '\\\\').Count - 1 }} else {{ 0 }}
  return $depth -le $maxDepth
}}
foreach($nm in $names) {{
  if($script:count -ge $maxResults) {{ break }}
  $remaining=$maxResults - $script:count
  Get-ChildItem -LiteralPath $base -Recurse -File -Filter $nm -EA 0 |
    Where-Object {{ !(IsExcluded $_.FullName) -and (InDepth $_.FullName) }} |
    Select-Object -First $remaining |
    ForEach-Object {{
      $full=$_.FullName
      $fv='';$pv='';$co='';$pn=''
      try {{ $vi=(Get-Item -LiteralPath $full).VersionInfo; $fv=$vi.FileVersion; $pv=$vi.ProductVersion; $co=$vi.CompanyName; $pn=$vi.ProductName }} catch {{}}
      [ordered]@{{kind='found'; base=$base; name=$_.Name; full=$full; fileVersion=($fv -as [string]); productVersion=($pv -as [string]); company=($co -as [string]); product=($pn -as [string])}} | ConvertTo-Json -Compress
      $script:count++
    }}
}}
""".strip()

    @staticmethod
    def prepare_action(action: Dict[str, Any]) -> str:
        """Process check/kill + backup + capture before-version/hash. Returns 'ready', 'blocked', or 'error'.
        Uses .NET methods exclusively — no PS cmdlet LiteralPath/version issues."""
        payload = base64.b64encode(json.dumps(action).encode("utf-8")).decode("ascii")
        return f"""
$ErrorActionPreference='Stop'
function Emit($o) {{ $o | ConvertTo-Json -Compress }}
function HashOf([string]$p) {{
  try {{
    $bytes=[System.IO.File]::ReadAllBytes($p)
    $sha=[System.Security.Cryptography.SHA256]::Create()
    $h=$sha.ComputeHash($bytes); $sha.Dispose()
    return ([BitConverter]::ToString($h) -replace '-','')
  }} catch {{ return '' }}
}}
function VersionOf([string]$p) {{
  try {{ return ([System.Diagnostics.FileVersionInfo]::GetVersionInfo($p).FileVersion -as [string]) }} catch {{ return '' }}
}}
function SafeName([string]$s) {{ return ($s -replace '[^A-Za-z0-9_.-]','_') }}
function ClearReadOnly([string]$f) {{
  try {{
    $fi=[System.IO.FileInfo]::new($f)
    $ro=[System.IO.FileAttributes]::ReadOnly
    if($fi.Attributes -band $ro) {{ $fi.Attributes=$fi.Attributes -bxor $ro }}
  }} catch {{ }}
}}
$a=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{payload}')) | ConvertFrom-Json
$target=[string]$a.target
$filename=[string]$a.filename
$rule=[string]$a.rule
$backup=[bool]$a.backup
$procMode=[string]$a.process_handling
$sourceType=[string]$a.source_type
$homeDir=[string]$a.home
if(-not $homeDir) {{
  $pd=[System.IO.Path]::GetDirectoryName($target)
  $leaf=[System.IO.Path]::GetFileName($pd)
  if($leaf -ieq 'bin') {{ $homeDir=[System.IO.Path]::GetDirectoryName($pd) }} else {{ $homeDir=$pd }}
}}
try {{
  [System.IO.Directory]::CreateDirectory('{REMOTE_BACKUPS}') | Out-Null
  if(![System.IO.File]::Exists($target)) {{ throw "Target not found: $target" }}
  $running=@()
  try {{
    $running=@(Get-Process -EA 0 | Where-Object {{
      $pp=$null
      try {{ $pp=$_.Path }} catch {{ }}
      if(-not $pp) {{ try {{ $pp=$_.MainModule.FileName }} catch {{ }} }}
      $pp -and ($pp -ieq $target)
    }})
  }} catch {{ $running=@() }}
  if($running.Count -gt 0) {{
    if($procMode -eq 'block') {{
      Emit ([ordered]@{{kind='blocked'; code='RUNNING_PROCESS'; rule=$rule; message=("Process running: "+(($running|ForEach-Object{{$_.ProcessName+':'+$_.Id}})-join', '))}}); exit 0
    }} elseif($procMode -eq 'kill') {{
      $pids=$running|ForEach-Object{{$_.Id}}
      $running|Stop-Process -Force -EA 0
      $waited=0
      while($waited -lt 15) {{
        Start-Sleep -Seconds 1; $waited++
        $still=@(Get-Process -EA 0|Where-Object{{$pids -contains $_.Id}})
        if($still.Count -eq 0) {{ break }}
      }}
    }}
  }}
  try {{
    if($sourceType -eq 'folder_overlay') {{
      & takeown /f $homeDir /r /d y 2>&1 | Out-Null
      & icacls $homeDir /grant "*S-1-5-32-544:(OI)(CI)F" /t /c /q 2>&1 | Out-Null
      & attrib -r -s -h $homeDir /s /d 2>&1 | Out-Null
      try {{
        foreach($f in [System.IO.Directory]::GetFiles($homeDir,'*',[System.IO.SearchOption]::AllDirectories)) {{
          ClearReadOnly $f
        }}
      }} catch {{ }}
    }} else {{
      & takeown /f $target /a 2>&1 | Out-Null
      & icacls $target /grant "*S-1-5-32-544:(F)" /c /q 2>&1 | Out-Null
      & attrib -r -s -h $target 2>&1 | Out-Null
      ClearReadOnly $target
    }}
  }} catch {{ }}
  $beforeVer=VersionOf $target
  $beforeHash=HashOf $target
  $backupPath=''
  $ts=Get-Date -Format yyyyMMdd_HHmmss
  if($backup) {{
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    if($sourceType -eq 'folder_overlay') {{
      if(![System.IO.Directory]::Exists($homeDir)) {{ throw "Home folder not found: $homeDir" }}
      $backupPath=[System.IO.Path]::Combine('{REMOTE_BACKUPS}',$ts+'__HOME__'+(SafeName([System.IO.Path]::GetFileName($homeDir)))+'.zip')
      if([System.IO.File]::Exists($backupPath)) {{ [System.IO.File]::Delete($backupPath) }}
      try {{
        $zip=[System.IO.Compression.ZipFile]::Open($backupPath,'Create')
        try {{
          foreach($f in [System.IO.Directory]::GetFiles($homeDir,'*',[System.IO.SearchOption]::AllDirectories)) {{
            $rel=$f.Substring($homeDir.Length).TrimStart('\')
            try {{ [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip,$f,$rel)|Out-Null }} catch {{ }}
          }}
        }} finally {{ $zip.Dispose() }}
      }} catch {{ $backupPath='' }}
    }} else {{
      $backupPath=[System.IO.Path]::Combine('{REMOTE_BACKUPS}',$ts+'__'+(SafeName $filename)+'.zip')
      if([System.IO.File]::Exists($backupPath)) {{ [System.IO.File]::Delete($backupPath) }}
      $zip=[System.IO.Compression.ZipFile]::Open($backupPath,'Create')
      try {{ [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip,$target,$filename)|Out-Null }} finally {{ $zip.Dispose() }}
    }}
    if($backupPath -and ![System.IO.File]::Exists($backupPath)) {{ throw 'Backup zip was not created' }}
  }}
  Emit ([ordered]@{{kind='ready'; rule=$rule; beforeVersion=$beforeVer; beforeHash=$beforeHash; backupPath=$backupPath}})
}} catch {{
  Emit ([ordered]@{{kind='error'; rule=$rule; message=$_.Exception.Message}})
}}
""".strip()

    @staticmethod
    def verify_action(action: Dict[str, Any]) -> str:
        """Read after-version/hash and confirm the copy succeeded. Returns 'success' or 'error'.
        Uses .NET methods exclusively — no PS cmdlet LiteralPath/version issues."""
        payload = base64.b64encode(json.dumps(action).encode("utf-8")).decode("ascii")
        return f"""
$ErrorActionPreference='Stop'
function Emit($o) {{ $o | ConvertTo-Json -Compress }}
function HashOf([string]$p) {{
  try {{
    $bytes=[System.IO.File]::ReadAllBytes($p)
    $sha=[System.Security.Cryptography.SHA256]::Create()
    $h=$sha.ComputeHash($bytes); $sha.Dispose()
    return ([BitConverter]::ToString($h) -replace '-','')
  }} catch {{ return '' }}
}}
function VersionOf([string]$p) {{
  try {{ return ([System.Diagnostics.FileVersionInfo]::GetVersionInfo($p).FileVersion -as [string]) }} catch {{ return '' }}
}}
$a=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{payload}')) | ConvertFrom-Json
$target=[string]$a.target
$rule=[string]$a.rule
$sourceHash=[string]$a.source_hash
$verify=[bool]$a.verify_hash
$probeRel=[string]$a.probe_relative
$sourceType=[string]$a.source_type
$homeDir=[string]$a.home
if(-not $homeDir) {{
  $pd=[System.IO.Path]::GetDirectoryName($target)
  $leaf=[System.IO.Path]::GetFileName($pd)
  if($leaf -ieq 'bin') {{ $homeDir=[System.IO.Path]::GetDirectoryName($pd) }} else {{ $homeDir=$pd }}
}}
try {{
  if(![System.IO.File]::Exists($target)) {{ throw "Target not found after copy: $target" }}
  $afterVer=VersionOf $target
  $afterHash=HashOf $target
  if($verify -and $sourceHash) {{
    if($sourceType -eq 'single_file') {{
      if($afterHash -ne $sourceHash) {{ throw "Hash mismatch: expected $sourceHash got $afterHash" }}
    }} elseif($sourceType -eq 'folder_overlay' -and $probeRel) {{
      $dstProbe=[System.IO.Path]::Combine($homeDir,$probeRel)
      $dstHash=HashOf $dstProbe
      if($dstHash -ne $sourceHash) {{ throw "Probe hash mismatch: expected $sourceHash got $dstHash" }}
    }}
  }}
  Emit ([ordered]@{{kind='success'; rule=$rule; afterVersion=$afterVer; afterHash=$afterHash; message='Completed'}})
}} catch {{
  Emit ([ordered]@{{kind='error'; rule=$rule; message=$_.Exception.Message}})
}}
""".strip()

# =============================================================================
# Engine
# =============================================================================

class RemediationEngine:
    def __init__(self, runner: PsExecRunner, uiq: queue.Queue):
        self.runner = runner
        self.uiq = uiq
        self.cancel = threading.Event()

    def discover_one(self, target: Target, filenames: List[str], max_depth: int, excludes: List[str], max_results: int) -> List[InventoryItem]:
        rows: List[InventoryItem] = []
        if self.cancel.is_set():
            return rows
        if not ping_host(target.host):
            rows.append(InventoryItem(target.host, "", "", "", status="OFFLINE", message="Ping failed"))
            return rows
        for base in target.bases:
            if self.cancel.is_set():
                break
            code, out, err = self.runner.run_ps(target.host, PS.discover(base, filenames, max_depth, excludes, max_results))
            if code != 0:
                rows.append(InventoryItem(target.host, base, "", "", status="ERROR", message=err or out))
                continue
            for obj in parse_json_lines(out):
                if obj.get("kind") == "found":
                    full = obj.get("full", "")
                    fv = obj.get("fileVersion", "") or ""
                    pv = obj.get("productVersion", "") or ""
                    fam = family_major_from_version(fv, pv, full)
                    rows.append(InventoryItem(
                        host=target.host,
                        base=obj.get("base", base),
                        filename=obj.get("name", ""),
                        full_path=full,
                        file_version=fv,
                        product_version=pv,
                        company=obj.get("company", "") or "",
                        product=obj.get("product", "") or "",
                        family=fam,
                        home=infer_home_from_file(full),
                        status="FOUND",
                        message="",
                    ))
                elif obj.get("kind") == "error":
                    rows.append(InventoryItem(target.host, obj.get("base", base), "", "", status=obj.get("code", "ERROR"), message=obj.get("message", "")))
        return rows

    def execute_plan_item(self, item: PlanItem, rule: Rule) -> AuditRow:
        ts = now_ts()
        if not ping_host(item.host):
            return AuditRow(ts, item.host, item.rule_name, item.filename, item.target_path, item.source_path, item.source_type, "OFFLINE", "Ping failed — host unreachable")

        def _psexec_err_detail(err: str) -> str:
            lines = err.strip().splitlines()
            return next((l for l in lines if l and not l.startswith(("PsExec", "Copyright", "Sysinternals", "http"))), err.strip())

        # Compute source hash locally before touching the remote
        source_hash = ""
        try:
            if rule.source_type == "single_file":
                source_hash = local_sha256(rule.source_path)
            else:
                probe = source_probe_file(rule)
                if probe:
                    source_hash = local_sha256(probe)
        except Exception as e:
            return AuditRow(ts, item.host, item.rule_name, item.filename, item.target_path, item.source_path, item.source_type, "ERROR", f"Cannot read source file: {e!r}")

        # --- Step 1: Prepare via PsExec (process check/kill + backup + before version/hash) ---
        before_ver = before_hash = backup_path = ""
        try:
            prep_action = {
                "rule": rule.name,
                "filename": item.filename,
                "target": item.target_path,
                "backup": rule.backup,
                "process_handling": rule.process_handling,
                "source_type": rule.source_type,
                "home": item.home,
            }
            code, out, err = self.runner.run_ps(item.host, PS.prepare_action(prep_action))
            if code != 0 and not out.strip():
                return AuditRow(ts, item.host, rule.name, item.filename, item.target_path, item.source_path, item.source_type, "ERROR", _psexec_err_detail(err) or f"PsExec exit code {code}")
            objs = parse_json_lines(out)
            prep = objs[-1] if objs else {"kind": "error", "message": err.strip() or "No output from prepare script"}
            if prep.get("kind") == "blocked":
                return AuditRow(ts, item.host, rule.name, item.filename, item.target_path, item.source_path, item.source_type, "BLOCKED", prep.get("message", ""))
            if prep.get("kind") != "ready":
                return AuditRow(ts, item.host, rule.name, item.filename, item.target_path, item.source_path, item.source_type, "ERROR", prep.get("message", "Prepare step failed"))
            before_ver = prep.get("beforeVersion", "")
            before_hash = prep.get("beforeHash", "")
            backup_path = prep.get("backupPath", "")
        except Exception as e:
            return AuditRow(ts, item.host, rule.name, item.filename, item.target_path, item.source_path, item.source_type, "ERROR", f"Prepare error: {e!r}")

        # --- Step 2: Copy directly to target via admin share (with retry for file-lock release) ---
        if not check_smb(item.host):
            return AuditRow(ts, item.host, rule.name, item.filename, item.target_path, item.source_path, item.source_type,
                            "ERROR", "TCP port 445 (SMB) is not reachable — admin share copy would fail. Check firewall.",
                            before_version=before_ver, before_hash=before_hash, backup_path=backup_path)
        copy_err: Optional[Exception] = None
        for attempt in range(3):
            try:
                if attempt > 0:
                    time.sleep(2)
                target_unc = admin_share_path(item.host, item.target_path)
                if rule.source_type == "single_file":
                    # Write to a temp name beside the target, then replace atomically
                    tmp_unc = target_unc + ".fleetpatch_tmp"
                    shutil.copy2(rule.source_path, tmp_unc)
                    if os.path.exists(target_unc):
                        os.replace(tmp_unc, target_unc)
                    else:
                        os.rename(tmp_unc, target_unc)
                elif rule.source_type == "folder_overlay":
                    if not item.home:
                        raise ValueError("Home directory not set for folder_overlay item")
                    home_unc = admin_share_path(item.host, item.home)
                    shutil.copytree(rule.source_path, home_unc, dirs_exist_ok=True)
                else:
                    raise ValueError(f"Unsupported source_type: {rule.source_type}")
                copy_err = None
                break
            except Exception as e:
                copy_err = e
        if copy_err is not None:
            return AuditRow(ts, item.host, rule.name, item.filename, item.target_path, item.source_path, item.source_type, "ERROR",
                            f"Copy failed after 3 attempts (check admin share \\\\{item.host}\\C$ is accessible and file is not locked): {copy_err}",
                            before_version=before_ver, before_hash=before_hash, backup_path=backup_path)

        # --- Step 3: Verify via PsExec (after-version/hash + hash check) ---
        try:
            ver_action = {
                "rule": rule.name,
                "target": item.target_path,
                "source_hash": source_hash,
                "verify_hash": rule.verify_hash,
                "probe_relative": probe_relative_path(rule),
                "source_type": rule.source_type,
                "home": item.home,
            }
            code, out, err = self.runner.run_ps(item.host, PS.verify_action(ver_action))
            if code != 0 and not out.strip():
                return AuditRow(ts, item.host, rule.name, item.filename, item.target_path, item.source_path, item.source_type, "ERROR", _psexec_err_detail(err) or f"PsExec exit code {code}", before_version=before_ver, before_hash=before_hash, backup_path=backup_path)
            objs = parse_json_lines(out)
            ver = objs[-1] if objs else {"kind": "error", "message": err.strip() or "No output from verify script"}
            result = {"success": "SUCCESS", "error": "ERROR"}.get(ver.get("kind", "error"), "ERROR")
            return AuditRow(
                timestamp=ts,
                host=item.host,
                rule_name=rule.name,
                filename=item.filename,
                target_path=item.target_path,
                source_path=item.source_path,
                source_type=item.source_type,
                result=result,
                message=ver.get("message", ""),
                before_version=before_ver,
                after_version=ver.get("afterVersion", ""),
                before_hash=before_hash,
                after_hash=ver.get("afterHash", ""),
                source_hash=source_hash,
                backup_path=backup_path,
            )
        except Exception as e:
            return AuditRow(ts, item.host, rule.name, item.filename, item.target_path, item.source_path, item.source_type, "ERROR", f"Verify error: {e!r}", before_version=before_ver, before_hash=before_hash, backup_path=backup_path)




# =============================================================================
# UI
# =============================================================================


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("1520x900")
        self.minsize(1250, 720)

        self.targets: List[Target] = []
        self.rules: List[Rule] = []
        self.inventory: List[InventoryItem] = []
        self.plan: List[PlanItem] = []
        self.audit: List[AuditRow] = []
        self.uiq: queue.Queue = queue.Queue()
        self.engine: Optional[RemediationEngine] = None

        self._build_ui()
        self.after(150, self._pump)

    def _build_ui(self):
        top = ttk.LabelFrame(self, text="Settings")
        top.pack(fill="x", padx=8, pady=6)
        self.var_psexec = tk.StringVar(value=r"C:\Tools\PsExec.exe")
        self.var_threads = tk.IntVar(value=8)
        self.var_depth = tk.IntVar(value=-1)
        self.var_max_results = tk.IntVar(value=200)
        ttk.Label(top, text="PsExec:").grid(row=0, column=0, sticky="w")
        ttk.Entry(top, textvariable=self.var_psexec, width=72).grid(row=0, column=1, sticky="w", padx=4)
        ttk.Button(top, text="Browse", command=self.pick_psexec).grid(row=0, column=2, padx=4)
        ttk.Label(top, text="Threads:").grid(row=0, column=3)
        ttk.Spinbox(top, from_=1, to=64, textvariable=self.var_threads, width=5).grid(row=0, column=4)
        ttk.Label(top, text="Max depth (-1 all):").grid(row=0, column=5, padx=(12, 2))
        ttk.Spinbox(top, from_=-1, to=50, textvariable=self.var_depth, width=5).grid(row=0, column=6)
        ttk.Label(top, text="Max results/base:").grid(row=0, column=7, padx=(12, 2))
        ttk.Spinbox(top, from_=1, to=10000, textvariable=self.var_max_results, width=7).grid(row=0, column=8)

        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=8, pady=4)
        self._tab_targets()
        self._tab_rules()
        self._tab_inventory()
        self._tab_plan()
        self._tab_audit()
        self._tab_log()

    def _tab_targets(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="1 Targets")
        bar = ttk.Frame(tab)
        bar.pack(fill="x", pady=4)
        ttk.Button(bar, text="Add", command=self.add_target).pack(side="left", padx=3)
        ttk.Button(bar, text="Import CSV/TXT", command=self.import_targets).pack(side="left", padx=3)
        ttk.Button(bar, text="Remove Selected", command=lambda: self.remove_selected(self.tree_targets, self.targets, self.refresh_targets)).pack(side="left", padx=3)
        ttk.Button(bar, text="Clear", command=lambda: (self.targets.clear(), self.refresh_targets())).pack(side="left", padx=3)
        frame, self.tree_targets = make_tree(tab, ["host", "bases"], 18)
        frame.pack(fill="both", expand=True)

    def _tab_rules(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="2 Rules Optional")
        bar = ttk.Frame(tab)
        bar.pack(fill="x", pady=4)
        ttk.Button(bar, text="Add Rule", command=self.add_rule).pack(side="left", padx=3)
        ttk.Button(bar, text="Edit Rule", command=self.edit_rule).pack(side="left", padx=3)
        ttk.Button(bar, text="Remove", command=self.remove_selected_rules).pack(side="left", padx=3)
        ttk.Button(bar, text="Import JSON", command=self.import_rules).pack(side="left", padx=3)
        ttk.Button(bar, text="Export JSON", command=self.export_rules).pack(side="left", padx=3)
        ttk.Button(bar, text="Refresh Source Metadata", command=self.refresh_rule_metadata).pack(side="left", padx=3)
        ttk.Label(tab, text="Rules are optional for Discovery. You only need rules when building a remediation plan.").pack(anchor="w", padx=6)
        cols = ["enabled", "priority", "name", "filename", "family", "source_type", "source_path", "source_version", "replace_when", "process"]
        frame, self.tree_rules = make_tree(tab, cols, 18)
        frame.pack(fill="both", expand=True)

    def _tab_inventory(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="3 Inventory / Discovery")
        bar = ttk.Frame(tab)
        bar.pack(fill="x", pady=4)
        self.var_discovery_files = tk.StringVar(value="java.exe")
        ttk.Label(bar, text="Find filenames:").pack(side="left", padx=(3, 2))
        ttk.Entry(bar, textvariable=self.var_discovery_files, width=55).pack(side="left", padx=3)
        ttk.Label(bar, text="comma/semicolon/space separated; rules not required").pack(side="left", padx=4)
        ttk.Button(bar, text="Run Discovery", command=self.run_discovery).pack(side="left", padx=8)
        ttk.Button(bar, text="Use Enabled Rule Filenames", command=self.fill_discovery_from_rules).pack(side="left", padx=3)
        ttk.Button(bar, text="Export CSV", command=lambda: self.export_csv(self.inventory, "inventory.csv")).pack(side="left", padx=3)
        ttk.Button(bar, text="Clear", command=lambda: (self.inventory.clear(), self.refresh_inventory())).pack(side="left", padx=3)
        cols = ["host", "base", "filename", "full_path", "file_version", "product_version", "company", "family", "status", "message"]
        frame, self.tree_inventory = make_tree(tab, cols, 20)
        frame.pack(fill="both", expand=True)

    def _tab_plan(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="4 Plan / Dry Run")
        bar = ttk.Frame(tab)
        bar.pack(fill="x", pady=4)
        ttk.Button(bar, text="Build Plan", command=self.build_plan).pack(side="left", padx=3)
        ttk.Button(bar, text="Approve Selected REVIEW", command=self.approve_selected_plan).pack(side="left", padx=3)
        ttk.Button(bar, text="Export CSV", command=lambda: self.export_csv(self.plan, "plan.csv")).pack(side="left", padx=3)
        ttk.Button(bar, text="Clear", command=lambda: (self.plan.clear(), self.refresh_plan())).pack(side="left", padx=3)
        cols = ["status", "host", "filename", "target_version", "source_version", "target_family", "source_family", "rule_name", "reason", "target_path", "source_path"]
        frame, self.tree_plan = make_tree(tab, cols, 20)
        frame.pack(fill="both", expand=True)

    def _tab_audit(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="5 Execute / Audit")
        bar = ttk.Frame(tab)
        bar.pack(fill="x", pady=4)
        ttk.Button(bar, text="Execute OK Plan Items", command=self.execute_plan).pack(side="left", padx=3)
        ttk.Button(bar, text="Cancel", command=self.cancel_jobs).pack(side="left", padx=3)
        ttk.Button(bar, text="Export CSV", command=lambda: self.export_csv(self.audit, "audit.csv")).pack(side="left", padx=3)
        ttk.Button(bar, text="Clear", command=lambda: (self.audit.clear(), self.refresh_audit())).pack(side="left", padx=3)
        cols = ["timestamp", "result", "host", "rule_name", "filename", "target_path", "message", "version_delta", "backup_path", "verify_status"]
        frame, self.tree_audit = make_tree(tab, cols, 20)
        frame.pack(fill="both", expand=True)

    def _tab_log(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="Log")
        self.txt_log = tk.Text(tab, height=10)
        self.txt_log.pack(fill="both", expand=True)

    # ------------------------------------------------------------------
    # UI common
    # ------------------------------------------------------------------
    def log(self, msg: str):
        self.txt_log.insert("end", f"[{ui_ts()}] {msg}\n")
        self.txt_log.see("end")

    def pick_psexec(self):
        p = filedialog.askopenfilename(title="Select PsExec.exe", filetypes=[("PsExec", "PsExec*.exe"), ("EXE", "*.exe"), ("All", "*.*")])
        if p:
            self.var_psexec.set(p)

    def get_engine(self) -> RemediationEngine:
        runner = PsExecRunner(self.var_psexec.get(), timeout_sec=900, run_as_system=True)
        self.engine = RemediationEngine(runner, self.uiq)
        return self.engine

    def remove_selected(self, tree: ttk.Treeview, backing: list, refresh):
        # Use iid (set to str(list_index) by all refresh_* methods) rather than
        # display position, so it works correctly when the grid is sorted.
        idxs = sorted([int(x) for x in tree.selection()], reverse=True)
        for i in idxs:
            if 0 <= i < len(backing):
                backing.pop(i)
        refresh()

    def remove_selected_rules(self):
        idxs = sorted([int(x) for x in self.tree_rules.selection()], reverse=True)
        for i in idxs:
            if 0 <= i < len(self.rules):
                self.rules.pop(i)
        self.refresh_rules()

    def add_target(self):
        d = SimpleTargetDialog(self)
        self.wait_window(d)
        if d.result:
            self.targets.append(d.result)
            self.refresh_targets()

    def import_targets(self):
        p = filedialog.askopenfilename(filetypes=[("CSV/TXT", "*.csv *.txt"), ("All", "*.*")])
        if not p:
            return
        seen = {t.host.lower() for t in self.targets}
        with open(p, newline="", encoding="utf-8-sig") as f:
            sample = f.read(2048)
            f.seek(0)
            if "," in sample:
                for row in csv.DictReader(f):
                    host = (row.get("host") or row.get("Host") or next(iter(row.values()), "")).strip()
                    bases = [x.strip() for x in (row.get("bases") or row.get("Bases") or "").split(";") if x.strip()] or list(DEFAULT_BASES)
                    if host and host.lower() not in seen:
                        self.targets.append(Target(host, bases))
                        seen.add(host.lower())
            else:
                for line in f:
                    host = line.strip().split(",")[0]
                    if host and host.lower() not in seen:
                        self.targets.append(Target(host))
                        seen.add(host.lower())
        self.refresh_targets()

    def add_rule(self):
        d = RuleDialog(self)
        self.wait_window(d)
        if d.result:
            self.rules.append(d.result)
            self.refresh_rule_metadata()
            self.refresh_rules()

    def edit_rule(self):
        sel = self.tree_rules.selection()
        if not sel:
            return
        idx = int(sel[0])
        d = RuleDialog(self, self.rules[idx])
        self.wait_window(d)
        if d.result:
            self.rules[idx] = d.result
            self.refresh_rule_metadata()
            self.refresh_rules()

    def duplicate_rule(self):
        sel = self.tree_rules.selection()
        if not sel:
            messagebox.showinfo("Duplicate", "Select a rule to duplicate first.")
            return
        idx = int(sel[0])
        if 0 <= idx < len(self.rules):
            orig = self.rules[idx]
            duped = Rule(**{**asdict(orig), "name": orig.name + " (copy)"})
            self.rules.append(duped)
            self.refresh_rule_metadata()
            self.log(f"Duplicated rule '{orig.name}'")

    def fill_discovery_from_rules(self):
        names = sorted({r.filename for r in self.rules if r.enabled and r.filename})
        if not names:
            messagebox.showinfo("Discovery", "No enabled rules with filenames found.")
            return
        self.var_discovery_files.set(", ".join(names))
        self.nb.select(2)

    def refresh_rule_metadata(self):
        for r in self.rules:
            r.source_file_version = r.source_product_version = r.source_sha256 = ""
            src = source_probe_file(r)
            if src and os.path.isfile(src):
                try:
                    r.source_sha256 = local_sha256(src)
                except Exception:
                    pass
                ps = f"$vi=(Get-Item -LiteralPath '{ps_sq(src)}').VersionInfo; [ordered]@{{fv=($vi.FileVersion -as [string]); pv=($vi.ProductVersion -as [string])}} | ConvertTo-Json -Compress"
                code, out, _ = run_local(["powershell.exe", "-NoProfile", "-Command", ps], timeout=20)
                if code == 0:
                    try:
                        o = json.loads(out)
                        r.source_file_version = o.get("fv", "") or ""
                        r.source_product_version = o.get("pv", "") or ""
                    except Exception:
                        pass
        self.refresh_rules()

    def import_rules(self):
        p = filedialog.askopenfilename(filetypes=[("JSON", "*.json"), ("All", "*.*")])
        if not p:
            return
        try:
            with open(p, encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception as e:
            messagebox.showerror("Import error", f"Could not read file:\n{e}")
            return
        valid_keys = {f.name for f in fields(Rule)}
        imported, errors = [], []
        for i, x in enumerate(data):
            try:
                imported.append(Rule(**{k: v for k, v in x.items() if k in valid_keys}))
            except Exception as e:
                errors.append(f"Rule {i + 1}: {e!r}")
        self.rules = imported
        self.refresh_rule_metadata()
        summary = f"Imported {len(imported)} rule(s) from {os.path.basename(p)}."
        if errors:
            summary += f"  {len(errors)} skipped."
            self.log("Rule import warnings: " + " | ".join(errors[:8]))
            messagebox.showwarning("Import complete", summary)
        else:
            self.log(summary)
            messagebox.showinfo("Import complete", summary)

    def export_rules(self):
        p = filedialog.asksaveasfilename(defaultextension=".json", initialfile="rules.json",
                                         filetypes=[("JSON", "*.json"), ("All", "*.*")])
        if not p:
            return
        try:
            with open(p, "w", encoding="utf-8") as fh:
                json.dump([asdict(r) for r in self.rules], fh, indent=2)
            self.log(f"Exported {len(self.rules)} rule(s) to {os.path.basename(p)}")
            messagebox.showinfo("Export complete", f"Exported {len(self.rules)} rule(s) to {os.path.basename(p)}")
        except Exception as e:
            self.log(f"Export rules error: {e!r}")
            messagebox.showerror("Export error", repr(e))

    # ------------------------------------------------------------------
    # Refresh grids
    # ------------------------------------------------------------------
    def refresh_targets(self):
        self.tree_targets.delete(*self.tree_targets.get_children())
        for t in self.targets:
            self.tree_targets.insert("", "end", values=[t.host, "; ".join(t.bases)])

    def refresh_rules(self):
        self.tree_rules.delete(*self.tree_rules.get_children())
        for idx, r in sorted(enumerate(self.rules), key=lambda pair: (pair[1].priority, pair[1].name.lower())):
            self.tree_rules.insert("", "end", iid=str(idx), values=[r.enabled, r.priority, r.name, r.filename, r.match_family, r.source_type, r.source_path, r.source_file_version, r.replace_when, r.process_handling])

    def refresh_inventory(self):
        self.tree_inventory.delete(*self.tree_inventory.get_children())
        for x in self.inventory:
            self.tree_inventory.insert("", "end", values=[x.host, x.base, x.filename, x.full_path, x.file_version, x.product_version, x.company, x.family, x.status, x.message])

    def refresh_plan(self):
        self.tree_plan.delete(*self.tree_plan.get_children())
        for x in self.plan:
            self.tree_plan.insert("", "end", values=[x.status, x.host, x.filename, x.target_version, x.source_version, x.target_family, x.source_family, x.rule_name, x.reason, x.target_path, x.source_path])

    def refresh_audit(self):
        self.tree_audit.delete(*self.tree_audit.get_children())
        for x in self.audit:
            self.tree_audit.insert("", "end", values=[x.timestamp, x.result, x.host, x.rule_name, x.filename, x.target_path, x.message, _version_delta(x), x.backup_path, x.verify_status])

    # ------------------------------------------------------------------
    # Discovery / plan / execute
    # ------------------------------------------------------------------
    def get_discovery_filenames(self) -> List[str]:
        names = split_filename_list(self.var_discovery_files.get())
        if names:
            return names
        # Optional fallback: if user left discovery blank but has rules, use enabled rule filenames.
        return sorted({r.filename for r in self.rules if r.enabled and r.filename})

    def run_discovery(self):
        if not self.targets:
            messagebox.showerror("Error", "Add targets first.")
            return
        filenames = self.get_discovery_filenames()
        if not filenames:
            messagebox.showerror("Error", "Enter one or more filenames to discover, for example: java.exe, javaw.exe. Rules are optional.")
            return
        self.inventory.clear()
        self.refresh_inventory()
        eng = self.get_engine()
        eng.cancel.clear()
        self.log(f"Discovery started for {len(self.targets)} host(s), filenames={filenames}")

        def worker():
            with ThreadPoolExecutor(max_workers=max(1, self.var_threads.get())) as pool:
                futs = [pool.submit(eng.discover_one, t, filenames, self.var_depth.get(), DEFAULT_EXCLUDES, self.var_max_results.get()) for t in self.targets]
                for fut in as_completed(futs):
                    try:
                        for row in fut.result():
                            self.uiq.put(("inventory", row))
                    except Exception as e:
                        self.uiq.put(("log", f"Discovery worker error: {e!r}"))
            self.uiq.put(("log", "Discovery completed."))
        threading.Thread(target=worker, daemon=True).start()

    def build_plan(self):
        if not self.inventory:
            messagebox.showerror("Error", "Run discovery first.")
            return
        # Specific rules (match_family set) sort before catch-all rules at the same priority level
        rules = sorted([r for r in self.rules if r.enabled], key=lambda r: (r.priority, 0 if r.match_family else 1, r.name.lower()))
        if not rules:
            messagebox.showinfo("Rules required", "Discovery can run without rules, but Build Plan requires at least one enabled rule.")
            return
        self.plan.clear()
        flagged_hosts: set = set()
        for inv in self.inventory:
            if inv.status != "FOUND":
                if inv.host not in flagged_hosts:
                    flagged_hosts.add(inv.host)
                    self.plan.append(PlanItem(
                        host=inv.host, base=inv.base, filename="", target_path="",
                        target_version="", target_family="", rule_name="",
                        source_path="", source_type="", source_version="", source_family="",
                        status=inv.status, reason=inv.message or inv.status,
                    ))
                continue
            tfam = inv.family or family_major_from_version(inv.file_version, inv.product_version, inv.full_path)
            matched: Optional[Rule] = None
            for r in rules:
                if inv.filename.lower() != r.filename.lower():
                    continue
                if r.match_family and tfam != r.match_family.strip():
                    continue
                matched = r
                break
            if not matched:
                filename_has_rules = any(r.filename.lower() == inv.filename.lower() for r in rules)
                if filename_has_rules and not tfam:
                    skip_reason = "Rules exist for this file but family could not be determined — check version info or install path"
                elif filename_has_rules:
                    skip_reason = f"No rule matches family '{tfam}' — add a rule with match_family='{tfam}' or leave match_family blank"
                else:
                    skip_reason = "No matching rule"
                self.plan.append(PlanItem(inv.host, inv.base, inv.filename, inv.full_path, inv.file_version, inv.family, "", "", "", "", "", "SKIP", skip_reason, inv.home))
                continue

            r = matched
            src_ver = r.source_file_version
            src_probe = source_probe_file(r)
            src_family = family_major_from_version(r.source_file_version, r.source_product_version, src_probe or r.source_path)
            status, reason = "OK", "Matched rule"

            if r.replace_when == "inventory_only":
                status, reason = "SKIP", "Inventory-only rule"
            elif not os.path.exists(r.source_path):
                status, reason = "BLOCKED", "Source path not found locally"
            elif r.source_type == "single_file" and os.path.isdir(r.source_path):
                status, reason = "BLOCKED", "Single-file rule points to a folder"
            elif r.source_type == "folder_overlay" and not os.path.isdir(r.source_path):
                status, reason = "BLOCKED", "Folder-overlay rule needs a source folder"
            elif r.source_type == "folder_overlay" and not probe_relative_path(r) and r.verify_hash:
                status, reason = "BLOCKED", "Folder overlay source probe file not found; hash verification unavailable"
            elif r.enforce_family_lock and r.match_family and src_family and r.match_family.strip() != src_family:
                status, reason = "BLOCKED", f"Rule '{r.name}' declares family={r.match_family} but source binary is family={src_family} — fix source_path in this rule"

            if status == "OK" and r.block_if_unknown_version and not inv.file_version and r.replace_when != "always":
                status, reason = "BLOCKED", "Target version unknown"
            if status == "OK" and r.replace_when == "if_older":
                cmp = compare_versions(inv.file_version, src_ver)
                if inv.file_version and src_ver and cmp >= 0:
                    status, reason = "SKIP", "Target is not older than source"
                elif not src_ver:
                    status, reason = "BLOCKED", "Source version unknown; cannot determine if older"
            if status == "OK" and r.replace_when == "if_different" and inv.file_version and src_ver and compare_versions(inv.file_version, src_ver) == 0:
                status, reason = "SKIP", "Target already matches source version"

            self.plan.append(PlanItem(inv.host, inv.base, inv.filename, inv.full_path, inv.file_version, inv.family, r.name, r.source_path, r.source_type, src_ver, src_family, status, reason, inv.home))
        self.refresh_plan()
        self.nb.select(3)
        self.log(f"Plan built: {len(self.plan)} row(s)")

    def approve_selected_plan(self):
        changed = 0
        for sel in self.tree_plan.selection():
            idx = self.tree_plan.index(sel)
            if 0 <= idx < len(self.plan) and self.plan[idx].status == "REVIEW":
                self.plan[idx].status = "OK"
                self.plan[idx].reason = "Manually approved from REVIEW. Use with caution."
                changed += 1
        self.refresh_plan()
        self.log(f"Approved {changed} REVIEW plan item(s).")

    def execute_plan(self):
        ok_items = [p for p in self.plan if p.status == "OK"]
        if not ok_items:
            messagebox.showinfo("Nothing to do", "No OK plan items to execute. REVIEW rows must be approved first; BLOCKED rows must be fixed.")
            return
        if not messagebox.askyesno("Confirm Execute", f"Execute {len(ok_items)} OK item(s)? This will modify remote files."):
            return
        eng = self.get_engine()
        eng.cancel.clear()
        rule_map = {r.name: r for r in self.rules}
        self.log(f"Execution started for {len(ok_items)} item(s)")

        def worker():
            with ThreadPoolExecutor(max_workers=max(1, min(self.var_threads.get(), 16))) as pool:
                futs = []
                for item in ok_items:
                    rule = rule_map.get(item.rule_name)
                    if rule:
                        futs.append(pool.submit(eng.execute_plan_item, item, rule))
                for fut in as_completed(futs):
                    try:
                        self.uiq.put(("audit", fut.result()))
                    except Exception as e:
                        self.uiq.put(("log", f"Execution worker error: {e!r}"))
            self.uiq.put(("log", "Execution completed."))
        threading.Thread(target=worker, daemon=True).start()

    def cancel_jobs(self):
        if self.engine:
            self.engine.cancel.set()
            self.engine.runner.kill_all()
        self.log("Cancel requested.")

    def export_csv(self, rows: list, default_name: str):
        if not rows:
            messagebox.showinfo("Export", "No rows to export.")
            return
        p = filedialog.asksaveasfilename(defaultextension=".csv", initialfile=default_name)
        if not p:
            return
        with open(p, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=list(asdict(rows[0]).keys()))
            w.writeheader()
            for r in rows:
                w.writerow(asdict(r))
        self.log(f"Exported {len(rows)} rows to {p}")

    def _pump(self):
        try:
            while True:
                kind, data = self.uiq.get_nowait()
                if kind == "inventory":
                    self.inventory.append(data)
                    self.refresh_inventory()
                elif kind == "audit":
                    self.audit.append(data)
                    self.refresh_audit()
                elif kind == "log":
                    self.log(str(data))
        except queue.Empty:
            pass
        self.after(150, self._pump)

# =============================================================================
# Dialogs
# =============================================================================

class SimpleTargetDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Add Target")
        self.result = None
        self.resizable(False, False)
        self.host = tk.StringVar()
        self.bases = tk.StringVar(value="; ".join(DEFAULT_BASES))
        ttk.Label(self, text="Host:").grid(row=0, column=0, sticky="w", padx=8, pady=6)
        ttk.Entry(self, textvariable=self.host, width=40).grid(row=0, column=1, padx=8, pady=6)
        ttk.Label(self, text="Bases ; separated:").grid(row=1, column=0, sticky="w", padx=8, pady=6)
        ttk.Entry(self, textvariable=self.bases, width=75).grid(row=1, column=1, padx=8, pady=6)
        bar = ttk.Frame(self)
        bar.grid(row=2, column=0, columnspan=2, pady=8)
        ttk.Button(bar, text="OK", command=self.ok).pack(side="left", padx=4)
        ttk.Button(bar, text="Cancel", command=self.destroy).pack(side="left", padx=4)
        self.grab_set()

    def ok(self):
        host = self.host.get().strip()
        bases = [x.strip() for x in self.bases.get().split(";") if x.strip()]
        if host:
            self.result = Target(host, bases or list(DEFAULT_BASES))
            self.destroy()


class RuleDialog(tk.Toplevel):
    # Human-readable label  ↔  internal value pairs
    _SOURCE_TYPES = [("Single file", "single_file"), ("Folder overlay", "folder_overlay")]
    _REPLACE_WHEN = [
        ("Replace if older",          "if_older"),
        ("Replace if different",      "if_different"),
        ("Always replace",            "always"),
        ("Inventory only (no replace)", "inventory_only"),
    ]
    _PROCESS = [
        ("Block if running",     "block"),
        ("Kill process first",   "kill"),
        ("Ignore (replace anyway)", "ignore"),
    ]

    @staticmethod
    def _to_disp(opts, internal):
        return next((d for d, i in opts if i == internal), internal)

    @staticmethod
    def _to_internal(opts, display):
        return next((i for d, i in opts if d == display), display)

    def __init__(self, parent, rule: Optional[Rule] = None):
        super().__init__(parent)
        is_new = rule is None
        r = rule or Rule(name="")
        self.title("Add Rule" if is_new else f"Edit Rule — {r.name}")
        self.result = None
        self.resizable(True, False)
        self.minsize(580, 0)

        self.vars: Dict[str, tk.Variable] = {
            "name":                     tk.StringVar(value=r.name),
            "enabled":                  tk.BooleanVar(value=r.enabled),
            "priority":                 tk.IntVar(value=r.priority),
            "filename":                 tk.StringVar(value=r.filename),
            "match_family":             tk.StringVar(value=r.match_family),
            "source_path":              tk.StringVar(value=r.source_path),
            "source_type":              tk.StringVar(value=self._to_disp(self._SOURCE_TYPES, r.source_type)),
            "replace_when":             tk.StringVar(value=self._to_disp(self._REPLACE_WHEN, r.replace_when)),
            "process_handling":         tk.StringVar(value=self._to_disp(self._PROCESS, r.process_handling)),
            "block_if_unknown_version": tk.BooleanVar(value=r.block_if_unknown_version),
            "enforce_family_lock":      tk.BooleanVar(value=r.enforce_family_lock),
            "backup":                   tk.BooleanVar(value=r.backup),
            "verify_hash":              tk.BooleanVar(value=r.verify_hash),
        }
        # Pre-populate source info from existing metadata if editing
        existing_info = ""
        if r.source_file_version:
            existing_info = f"Version: {r.source_file_version}"
            if r.source_sha256:
                existing_info += f"  |  SHA256: {r.source_sha256[:16]}…"
        self._source_info = tk.StringVar(value=existing_info)
        self._build()
        self.grab_set()

    def _build(self):
        # ── Identity ──────────────────────────────────────────────────────────
        id_frame = ttk.LabelFrame(self, text="Identity", padding=(10, 6))
        id_frame.pack(fill="x", padx=12, pady=(12, 4))
        id_frame.columnconfigure(1, weight=1)

        ttk.Label(id_frame, text="Rule name *").grid(row=0, column=0, sticky="w", pady=3)
        ttk.Entry(id_frame, textvariable=self.vars["name"]).grid(row=0, column=1, columnspan=2, sticky="ew", padx=(8, 0), pady=3)

        ttk.Label(id_frame, text="Enabled").grid(row=1, column=0, sticky="w", pady=3)
        ttk.Checkbutton(id_frame, variable=self.vars["enabled"]).grid(row=1, column=1, sticky="w", padx=(8, 0))

        ttk.Label(id_frame, text="Priority").grid(row=2, column=0, sticky="w", pady=3)
        ttk.Spinbox(id_frame, from_=1, to=9999, textvariable=self.vars["priority"], width=7).grid(row=2, column=1, sticky="w", padx=(8, 0), pady=3)
        ttk.Label(id_frame, text="Lower number runs first", foreground="#605e5c").grid(row=2, column=2, sticky="w", padx=6)

        ttk.Label(id_frame, text="Filename to find *").grid(row=3, column=0, sticky="w", pady=3)
        ttk.Entry(id_frame, textvariable=self.vars["filename"], width=26).grid(row=3, column=1, sticky="w", padx=(8, 0), pady=3)
        ttk.Label(id_frame, text="e.g.  java.exe", foreground="#605e5c").grid(row=3, column=2, sticky="w", padx=6)

        ttk.Label(id_frame, text="Version family filter").grid(row=4, column=0, sticky="w", pady=3)
        ttk.Entry(id_frame, textvariable=self.vars["match_family"], width=10).grid(row=4, column=1, sticky="w", padx=(8, 0), pady=3)
        ttk.Label(id_frame, text="8 / 11 / 17 …  leave blank to match any", foreground="#605e5c").grid(row=4, column=2, sticky="w", padx=6)

        # ── Replacement source ────────────────────────────────────────────────
        src_frame = ttk.LabelFrame(self, text="Replacement source", padding=(10, 6))
        src_frame.pack(fill="x", padx=12, pady=4)
        src_frame.columnconfigure(1, weight=1)

        ttk.Label(src_frame, text="Source type").grid(row=0, column=0, sticky="w", pady=3)
        ttk.Combobox(src_frame, textvariable=self.vars["source_type"],
                     values=[d for d, _ in self._SOURCE_TYPES],
                     state="readonly", width=22).grid(row=0, column=1, sticky="w", padx=(8, 0), pady=3)

        ttk.Label(src_frame, text="Source path").grid(row=1, column=0, sticky="w", pady=3)
        pf = ttk.Frame(src_frame)
        pf.grid(row=1, column=1, columnspan=2, sticky="ew", padx=(8, 0), pady=3)
        pf.columnconfigure(0, weight=1)
        ttk.Entry(pf, textvariable=self.vars["source_path"]).grid(row=0, column=0, sticky="ew")
        ttk.Button(pf, text="Browse…", command=self.browse).grid(row=0, column=1, padx=(4, 0))

        # Version / hash info — updated after browse
        ttk.Label(src_frame, textvariable=self._source_info,
                  foreground="#107c10", font=("Segoe UI", 8)).grid(row=2, column=0, columnspan=3, sticky="w", pady=(0, 2))

        # ── Behaviour ─────────────────────────────────────────────────────────
        beh_frame = ttk.LabelFrame(self, text="Behaviour", padding=(10, 6))
        beh_frame.pack(fill="x", padx=12, pady=4)
        beh_frame.columnconfigure(1, weight=1)

        ttk.Label(beh_frame, text="Replace when").grid(row=0, column=0, sticky="w", pady=3)
        ttk.Combobox(beh_frame, textvariable=self.vars["replace_when"],
                     values=[d for d, _ in self._REPLACE_WHEN],
                     state="readonly", width=30).grid(row=0, column=1, sticky="w", padx=(8, 0), pady=3)

        ttk.Label(beh_frame, text="If file is running").grid(row=1, column=0, sticky="w", pady=3)
        ttk.Combobox(beh_frame, textvariable=self.vars["process_handling"],
                     values=[d for d, _ in self._PROCESS],
                     state="readonly", width=24).grid(row=1, column=1, sticky="w", padx=(8, 0), pady=3)

        # ── Safety ────────────────────────────────────────────────────────────
        saf_frame = ttk.LabelFrame(self, text="Safety", padding=(10, 6))
        saf_frame.pack(fill="x", padx=12, pady=4)

        for text, key, hint in [
            ("Backup before replacing",           "backup",                   "Creates a ZIP backup on the remote host before any change"),
            ("Verify file hash after copy",       "verify_hash",              "SHA256 check confirms the file copied correctly"),
            ("Block if target version unknown",   "block_if_unknown_version", "Skip replacement when the target file has no version info"),
            ("Prevent cross-family replacement",  "enforce_family_lock",      "Stops replacing Java 8 with Java 11, etc."),
        ]:
            rf = ttk.Frame(saf_frame)
            rf.pack(fill="x", pady=2)
            ttk.Checkbutton(rf, variable=self.vars[key], text=text).pack(side="left")
            ttk.Label(rf, text=hint, foreground="#605e5c", font=("Segoe UI", 8)).pack(side="left", padx=(10, 0))

        # ── Buttons ───────────────────────────────────────────────────────────
        btn_bar = ttk.Frame(self)
        btn_bar.pack(fill="x", padx=12, pady=(8, 12))
        ttk.Button(btn_bar, text="Save rule", command=self.ok, style="Primary.TButton").pack(side="right", padx=(4, 0))
        ttk.Button(btn_bar, text="Cancel", command=self.destroy).pack(side="right")

    def browse(self):
        is_folder = "folder" in self.vars["source_type"].get().lower()
        p = filedialog.askdirectory(title="Select source folder") if is_folder \
            else filedialog.askopenfilename(title="Select source file")
        if not p:
            return
        self.vars["source_path"].set(p)
        self._source_info.set("Reading version info…")
        threading.Thread(target=self._refresh_source_info, daemon=True).start()

    def _refresh_source_info(self):
        """Runs in background thread — reads version + hash from the picked source."""
        src = self.vars["source_path"].get().strip()
        is_folder = "folder" in self.vars["source_type"].get().lower()
        probe = src
        if is_folder:
            fn = self.vars["filename"].get().strip() or "java.exe"
            for candidate in (os.path.join(src, "bin", fn), os.path.join(src, fn)):
                if os.path.isfile(candidate):
                    probe = candidate
                    break
            else:
                probe = ""
        if not probe or not os.path.isfile(probe):
            self.after(0, self._source_info.set, "Source file not found — check path and source type.")
            return
        ps = (f"$vi=(Get-Item -LiteralPath '{ps_sq(probe)}').VersionInfo; "
              f"[ordered]@{{fv=($vi.FileVersion -as [string]); pv=($vi.ProductVersion -as [string])}} | ConvertTo-Json -Compress")
        code, out, _ = run_local(["powershell.exe", "-NoProfile", "-Command", ps], timeout=15)
        fv = pv = ""
        if code == 0:
            try:
                o = json.loads(out.strip())
                fv = o.get("fv", "") or ""
                pv = o.get("pv", "") or ""
            except Exception:
                pass
        try:
            sha = local_sha256(probe)[:16] + "…"
        except Exception:
            sha = "?"
        parts = [f"Version: {fv}"] if fv else []
        if pv and pv != fv:
            parts.append(f"Product: {pv}")
        parts.append(f"SHA256: {sha}")
        self.after(0, self._source_info.set, "  |  ".join(parts))

    def ok(self):
        name = self.vars["name"].get().strip()
        filename = self.vars["filename"].get().strip()
        if not name:
            messagebox.showerror("Validation error", "Rule name is required.", parent=self)
            return
        if not filename:
            messagebox.showerror("Validation error", "Filename to find is required.", parent=self)
            return
        src_path = self.vars["source_path"].get().strip()
        src_type = self._to_internal(self._SOURCE_TYPES, self.vars["source_type"].get())
        if src_path and not os.path.exists(src_path):
            if not messagebox.askyesno("Source not found",
                    f"The source path does not exist on this machine:\n\n{src_path}\n\nSave rule anyway?",
                    parent=self):
                return
        self.result = Rule(
            name=name,
            enabled=self.vars["enabled"].get(),
            priority=int(self.vars["priority"].get()),
            filename=filename,
            match_family=self.vars["match_family"].get().strip(),
            source_path=src_path,
            source_type=src_type,
            replace_when=self._to_internal(self._REPLACE_WHEN, self.vars["replace_when"].get()),
            block_if_unknown_version=self.vars["block_if_unknown_version"].get(),
            enforce_family_lock=self.vars["enforce_family_lock"].get(),
            backup=self.vars["backup"].get(),
            verify_hash=self.vars["verify_hash"].get(),
            process_handling=self._to_internal(self._PROCESS, self.vars["process_handling"].get()),
        )
        self.destroy()


# =============================================================================
# Hardened Modern UI v2.3
# =============================================================================

def _int_var_value(var: tk.Variable, default: int, low: Optional[int] = None, high: Optional[int] = None) -> int:
    """Safely read a Tk integer variable and clamp it."""
    try:
        value = int(var.get())
    except Exception:
        value = default
    if low is not None:
        value = max(low, value)
    if high is not None:
        value = min(high, value)
    return value


def _parse_excludes(raw: str) -> List[str]:
    """Parse semicolon/comma/newline separated exclude paths."""
    parts = re.split(r"[;,\n\r]+", raw or "")
    return [normalize_win_path(x.strip()).rstrip("\\") for x in parts if x.strip()]


def _tree_set_columns(tree: ttk.Treeview, columns: List[str]) -> None:
    width_map = {
        "host": 150, "bases": 640, "enabled": 78, "priority": 82, "name": 190,
        "filename": 125, "family": 82, "source_type": 130, "source_path": 460,
        "source_version": 150, "replace_when": 135, "process": 95, "base": 230,
        "full_path": 570, "file_version": 155, "product_version": 160, "company": 190,
        "product": 190, "status": 105, "message": 430, "target_path": 570,
        "target_version": 155, "target_family": 105, "rule": 190, "source": 430,
        "source_family": 105, "reason": 430, "timestamp": 165, "result": 115,
        "rule_name": 190, "before_version": 150, "after_version": 150, "backup_path": 430,
    }
    for c in columns:
        tree.heading(c, text=c.replace("_", " ").title())
        tree.column(c, width=width_map.get(c, max(110, min(300, len(c) * 14))), anchor="w", stretch=True)


def make_tree_hardened(parent, columns: List[str], height: int = 14) -> Tuple[ttk.Frame, ttk.Treeview]:
    frame = ttk.Frame(parent, padding=(8, 6, 8, 8))
    tree = ttk.Treeview(frame, columns=columns, show="headings", height=height, selectmode="extended")
    y = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
    x = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
    tree.configure(yscrollcommand=y.set, xscrollcommand=x.set)
    tree.grid(row=0, column=0, sticky="nsew")
    y.grid(row=0, column=1, sticky="ns")
    x.grid(row=1, column=0, sticky="ew")
    frame.rowconfigure(0, weight=1)
    frame.columnconfigure(0, weight=1)
    _tree_set_columns(tree, columns)
    for tag, color in {
        "FOUND": "#107c10", "OK": "#107c10", "SUCCESS": "#107c10",
        "SKIP": "#605e5c", "REVIEW": "#8a6d00", "BLOCKED": "#a4262c",
        "ERROR": "#a4262c", "OFFLINE": "#a4262c",
    }.items():
        tree.tag_configure(tag, foreground=color)
    return frame, tree


def attach_sort_headers(tree: ttk.Treeview, get_data: Callable, cols: List[str], refresh_fn: Callable) -> None:
    """Bind column header clicks to sort the underlying data list in-place.

    Clicking the same column again reverses the sort order. An arrow suffix
    (▲/▼) is appended to the active sort column heading.
    """
    state: Dict[str, bool] = {}  # col -> currently_reversed

    def _make_cmd(col: str) -> Callable:
        def _sort():
            rev = state.get(col, False)
            try:
                get_data().sort(
                    key=lambda r: str(getattr(r, col, "") or "").lower(),
                    reverse=rev,
                )
            except Exception:
                pass
            state[col] = not rev
            refresh_fn()
            for c in cols:
                base = c.replace("_", " ").title()
                if c == col:
                    arrow = " ▼" if state[col] else " ▲"
                    tree.heading(c, text=base + arrow)
                else:
                    tree.heading(c, text=base)
        return _sort

    for c in cols:
        tree.heading(c, command=_make_cmd(c))


# =============================================================================
# CSV target import helpers v2.4
# =============================================================================
HOST_COLUMNS = {"host", "hostname", "computer", "computername", "computer_name", "machine", "server", "device", "target", "name"}
BASE_COLUMNS = {"bases", "base", "basepath", "base_path", "path", "folder", "location", "scanpath", "scan_path", "value", "filepath", "file_path"}


def _norm_col_name(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", (name or "").strip().lower()).strip("_")


def _split_base_paths(raw: str) -> List[str]:
    """Split one CSV path field into one or more scan bases.

    Semicolon is the primary separator so Windows drive letters like C:\ are safe.
    Newlines and pipe are also supported. Commas are intentionally NOT split here
    because CSV itself uses commas as field separators.
    """
    parts = re.split(r"[;|\n\r]+", raw or "")
    out: List[str] = []
    seen = set()
    for part in parts:
        p = normalize_win_path(part.strip().strip('"').strip("'"))
        if not p:
            continue
        # Trim trailing backslashes except drive roots such as C:\.
        if not re.match(r"^[A-Za-z]:\\$", p):
            p = p.rstrip("\\")
        key = p.lower()
        if key not in seen:
            out.append(p)
            seen.add(key)
    return out


def _looks_like_header(first_row: List[str]) -> bool:
    cols = {_norm_col_name(x) for x in first_row}
    return bool(cols & HOST_COLUMNS) and bool(cols & BASE_COLUMNS)


def parse_target_csv_rows(csv_path: str) -> Tuple[List[Target], List[str]]:
    """Parse target CSV/TXT into Target(host, bases).

    Accepted CSV headers:
      host/hostname/computer/computername/server/... plus
      bases/base/basepath/path/location/scan_path/...

    Also accepts old working two-column format with no header:
      HOST01,C:\Some\Base\Path

    Important safety rule: for CSV rows, a path is required. We do NOT silently
    fall back to DEFAULT_BASES when a CSV path is blank or missing.
    """
    warnings: List[str] = []
    by_host: Dict[str, Tuple[str, List[str]]] = {}

    def add(host: str, raw_paths: str, line_no: int) -> None:
        host = (host or "").strip().strip('"').strip("'")
        bases = _split_base_paths(raw_paths)
        if not host:
            warnings.append(f"Line {line_no}: skipped because host is blank")
            return
        if not bases:
            warnings.append(f"Line {line_no}: skipped {host} because path/base is blank")
            return
        key = host.lower()
        if key not in by_host:
            by_host[key] = (host, [])
        existing = by_host[key][1]
        existing_keys = {x.lower() for x in existing}
        for base in bases:
            if base.lower() not in existing_keys:
                existing.append(base)
                existing_keys.add(base.lower())

    with open(csv_path, newline="", encoding="utf-8-sig") as f:
        sample = f.read(4096)
        f.seek(0)
        # TXT or single-column file: keep old behavior, host only with default bases.
        # CSV with comma/semicolon delimiter should provide a path.
        if csv_path.lower().endswith(".txt") and "," not in sample:
            for line_no, line in enumerate(f, start=1):
                host = line.strip().split(",")[0]
                if host:
                    key = host.lower()
                    if key not in by_host:
                        by_host[key] = (host, list(DEFAULT_BASES))
            return [Target(host=h, bases=b) for h, b in by_host.values()], warnings

        reader = csv.reader(f)
        rows = list(reader)
        if not rows:
            return [], ["CSV is empty"]

        first = rows[0]
        if _looks_like_header(first):
            norm = [_norm_col_name(c) for c in first]
            host_idx = next((i for i, c in enumerate(norm) if c in HOST_COLUMNS), None)
            base_idx = next((i for i, c in enumerate(norm) if c in BASE_COLUMNS), None)
            for line_no, row in enumerate(rows[1:], start=2):
                if not row or not any((x or "").strip() for x in row):
                    continue
                host = row[host_idx].strip() if host_idx is not None and host_idx < len(row) else ""
                base = row[base_idx].strip() if base_idx is not None and base_idx < len(row) else ""
                add(host, base, line_no)
        else:
            # Old working logic: first two columns are host,path. Skip accidental header names.
            for line_no, row in enumerate(rows, start=1):
                if len(row) < 2:
                    warnings.append(f"Line {line_no}: skipped because it has fewer than 2 columns")
                    continue
                host, base = row[0].strip(), row[1].strip()
                if _norm_col_name(host) in HOST_COLUMNS or host.lower() in ("host", "hostname"):
                    continue
                add(host, base, line_no)

    return [Target(host=h, bases=b) for h, b in by_host.values()], warnings


def broad_base_paths(targets: List[Target]) -> List[str]:
    """Return broad scan bases that could look like a whole-drive scan."""
    broad: List[str] = []
    for t in targets:
        for base in t.bases:
            b = normalize_win_path(base).rstrip("\\").lower()
            if re.match(r"^[a-z]:$", b):
                broad.append(f"{t.host}: {base}")
    return broad


class HardenedApp(App):
    """Production-oriented UI wrapper around the original remediation engine.

    v2.4 keeps the original backend model and PsExec/PowerShell behavior, but
    replaces the front end with guarded callbacks, compatible widget names,
    safer export handling, validated numeric settings, optional excludes, and
    status/log resiliency.
    """

    def __init__(self):
        tk.Tk.__init__(self)
        self.title(APP_NAME)
        self.geometry("1600x950")
        self.minsize(1280, 760)

        self.targets: List[Target] = []
        self.rules: List[Rule] = []
        self.inventory: List[InventoryItem] = []
        self.plan: List[PlanItem] = []
        self.audit: List[AuditRow] = []
        self.uiq: queue.Queue = queue.Queue()
        self.engine: Optional[RemediationEngine] = None
        self._busy_jobs = 0
        self.status_text = tk.StringVar(value="Ready")

        self._configure_style()
        self._build_ui()
        self._set_status("Ready")
        self.after(150, self._pump)

    # ----------------------------- UI construction -----------------------------
    def _configure_style(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Header.TFrame", background="#0f3a5f")
        style.configure("HeaderTitle.TLabel", background="#0f3a5f", foreground="white", font=("Segoe UI", 16, "bold"))
        style.configure("HeaderSub.TLabel", background="#0f3a5f", foreground="#dcecff", font=("Segoe UI", 9))
        style.configure("Card.TLabelframe", padding=10)
        style.configure("Card.TLabelframe.Label", font=("Segoe UI", 10, "bold"))
        style.configure("Primary.TButton", font=("Segoe UI", 9, "bold"))
        style.configure("Danger.TButton", font=("Segoe UI", 9, "bold"))
        style.configure("Treeview", rowheight=25)
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))
        style.configure("Green.Horizontal.TProgressbar", background="#107c10", troughcolor="#e0e0e0", bordercolor="#e0e0e0")

    def _button(self, parent, text: str, command, primary: bool = False):
        return ttk.Button(parent, text=text, command=command, style="Primary.TButton" if primary else "TButton")

    def _toolbar(self, parent) -> ttk.Frame:
        bar = ttk.Frame(parent, padding=(8, 8, 8, 2))
        bar.pack(fill="x")
        return bar

    def _hint(self, parent, text: str) -> None:
        ttk.Label(parent, text=text, foreground="#605e5c", padding=(8, 0, 8, 4)).pack(anchor="w")

    def _build_ui(self):
        self.var_psexec = tk.StringVar(value=r"C:\Tools\PsExec.exe")
        self.var_threads = tk.IntVar(value=8)
        self.var_depth = tk.IntVar(value=-1)
        self.var_max_results = tk.IntVar(value=200)
        # Backward-compatible variable expected by original callbacks.
        self.var_discovery_files = tk.StringVar(value="java.exe\njavaw.exe")
        self.var_excludes = tk.StringVar(value="; ".join(DEFAULT_EXCLUDES))

        header = ttk.Frame(self, style="Header.TFrame", padding=(14, 12))
        header.pack(fill="x")
        ttk.Label(header, text=APP_NAME, style="HeaderTitle.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text="Hardened workflow: targets → optional rules → inventory → reviewed plan → audited execution.",
            style="HeaderSub.TLabel",
        ).pack(anchor="w", pady=(2, 0))

        top = ttk.LabelFrame(self, text="Connection and discovery settings", style="Card.TLabelframe")
        top.pack(fill="x", padx=10, pady=(8, 6))
        top.columnconfigure(1, weight=1)
        ttk.Label(top, text="PsExec.exe").grid(row=0, column=0, sticky="w", padx=(2, 6), pady=4)
        ttk.Entry(top, textvariable=self.var_psexec).grid(row=0, column=1, sticky="ew", padx=4, pady=4)
        self._button(top, "Browse", self.pick_psexec).grid(row=0, column=2, padx=4, pady=4)
        ttk.Label(top, text="Threads").grid(row=0, column=3, padx=(18, 4), pady=4)
        ttk.Spinbox(top, from_=1, to=64, textvariable=self.var_threads, width=6).grid(row=0, column=4, pady=4)
        ttk.Label(top, text="Depth").grid(row=0, column=5, padx=(18, 4), pady=4)
        ttk.Spinbox(top, from_=-1, to=50, textvariable=self.var_depth, width=6).grid(row=0, column=6, pady=4)
        ttk.Label(top, text="Max/base").grid(row=0, column=7, padx=(18, 4), pady=4)
        ttk.Spinbox(top, from_=1, to=10000, textvariable=self.var_max_results, width=8).grid(row=0, column=8, pady=4)

        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=10, pady=4)
        self._tab_targets()
        self._tab_inventory()
        self._tab_rules()
        self._tab_plan()
        self._tab_audit()
        self._tab_log()

        status = ttk.Frame(self, padding=(10, 4))
        status.pack(fill="x", side="bottom")
        ttk.Label(status, textvariable=self.status_text).pack(side="left")
        self._progress = ttk.Progressbar(status, mode="determinate", maximum=100, value=0, length=140, style="Green.Horizontal.TProgressbar")
        self._progress.pack(side="left", padx=(12, 0))
        self._progress_pct = tk.StringVar(value="")
        ttk.Label(status, textvariable=self._progress_pct, width=5, anchor="w").pack(side="left", padx=(4, 0))
        ttk.Label(status, text=fr"Remote backups: {REMOTE_BACKUPS}").pack(side="right")

    def _tab_targets(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="1  Targets")
        bar = self._toolbar(tab)
        self._button(bar, "Add target", self.add_target, True).pack(side="left", padx=3)
        self._button(bar, "Import CSV/TXT", self.import_targets).pack(side="left", padx=3)
        self._button(bar, "Save targets", self.save_targets).pack(side="left", padx=3)
        self._button(bar, "Remove selected", lambda: self.remove_selected(self.tree_targets, self.targets, self.refresh_targets)).pack(side="left", padx=3)
        self._button(bar, "Clear", lambda: (self.targets.clear(), self.refresh_targets())).pack(side="left", padx=3)
        self._hint(tab, "CSV accepted: hostname,path OR host,bases OR old two-column HOST,BASEPATH. Discovery scans ONLY these imported base paths. Use Depth=0 for exact-folder checks.")
        frame, self.tree_targets = make_tree_hardened(tab, ["host", "bases"], 18)
        frame.pack(fill="both", expand=True)

    def _tab_rules(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="3  Rules")
        bar = self._toolbar(tab)
        self._button(bar, "Add rule", self.add_rule, True).pack(side="left", padx=3)
        self._button(bar, "Edit rule", self.edit_rule).pack(side="left", padx=3)
        self._button(bar, "Duplicate", self.duplicate_rule).pack(side="left", padx=3)
        self._button(bar, "Remove", self.remove_selected_rules).pack(side="left", padx=3)
        self._button(bar, "Import JSON", self.import_rules).pack(side="left", padx=3)
        self._button(bar, "Export JSON", self.export_rules).pack(side="left", padx=3)
        self._button(bar, "Refresh source metadata", self.refresh_rule_metadata).pack(side="left", padx=3)
        self._hint(tab, "Rules are optional for inventory, but required for Build Plan. Double-click a row to edit.")
        cols = ["enabled", "priority", "name", "filename", "family", "source_type", "source_path", "source_version", "replace_when", "process"]
        frame, self.tree_rules = make_tree_hardened(tab, cols, 18)
        frame.pack(fill="both", expand=True)
        self.tree_rules.bind("<Double-1>", lambda _: self.edit_rule())

    def _tab_inventory(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="2  Inventory")
        search = ttk.LabelFrame(tab, text="Discovery input", style="Card.TLabelframe")
        search.pack(fill="x", padx=8, pady=(8, 4))
        search.columnconfigure(1, weight=1)
        ttk.Label(search, text="Filenames").grid(row=0, column=0, sticky="nw", padx=(0, 6), pady=4)
        self.txt_filenames = tk.Text(search, height=3, wrap="word")
        self.txt_filenames.insert("1.0", self.var_discovery_files.get())
        self.txt_filenames.grid(row=0, column=1, sticky="ew", pady=4)
        self._button(search, "Use filenames from rules", self.fill_discovery_from_rules).grid(row=0, column=2, sticky="n", padx=6, pady=4)
        ttk.Label(search, text="Excludes").grid(row=1, column=0, sticky="w", padx=(0, 6), pady=4)
        ttk.Entry(search, textvariable=self.var_excludes).grid(row=1, column=1, columnspan=2, sticky="ew", pady=4)

        bar = self._toolbar(tab)
        self._button(bar, "Run discovery", self.run_discovery, True).pack(side="left", padx=3)
        self._button(bar, "Build plan", self.build_plan).pack(side="left", padx=3)
        self._button(bar, "Export Excel", self.export_inventory_excel).pack(side="left", padx=3)
        self._button(bar, "Export full CSV", lambda: self.export_csv("inventory")).pack(side="left", padx=3)
        self._button(bar, "Clear", lambda: (self.inventory.clear(), self.refresh_inventory())).pack(side="left", padx=3)
        cols = ["host", "base", "filename", "full_path", "file_version", "product_version", "family", "company", "product", "status", "message"]
        frame, self.tree_inventory = make_tree_hardened(tab, cols, 15)
        frame.pack(fill="both", expand=True)

    def _tab_plan(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="4  Plan")
        bar = self._toolbar(tab)
        self._button(bar, "Build Plan", self.build_plan, True).pack(side="left", padx=3)
        self._button(bar, "Execute OK", self.execute_plan).pack(side="left", padx=3)
        self._button(bar, "Cancel running jobs", self.cancel_jobs).pack(side="left", padx=3)
        self._button(bar, "Export plan CSV", lambda: self.export_csv("plan")).pack(side="left", padx=3)
        self._button(bar, "Clear plan", lambda: (self.plan.clear(), self.refresh_plan())).pack(side="left", padx=3)
        self._hint(tab, "OK rows will be executed. SKIP = rule says no change needed or no rule matched. BLOCKED = must fix rule/source before executing.")
        cols = ["host", "filename", "target_path", "target_version", "target_family", "rule", "source_type", "source", "source_version", "source_family", "status", "reason"]
        frame, self.tree_plan = make_tree_hardened(tab, cols, 18)
        frame.pack(fill="both", expand=True)

    def _tab_audit(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="5  Audit")
        bar = self._toolbar(tab)
        self._button(bar, "Export audit CSV", lambda: self.export_csv("audit"), True).pack(side="left", padx=3)
        self._button(bar, "Retry failed", self.retry_failed).pack(side="left", padx=3)
        self._button(bar, "Clear audit", lambda: (self.audit.clear(), self.refresh_audit())).pack(side="left", padx=3)
        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=6)
        ttk.Label(bar, text="Filter:").pack(side="left")
        self.var_audit_filter = tk.StringVar(value="All")
        cb = ttk.Combobox(bar, textvariable=self.var_audit_filter, width=10,
                          values=["All", "SUCCESS", "ERROR", "OFFLINE", "BLOCKED", "SKIP"],
                          state="readonly")
        cb.pack(side="left", padx=4)
        cb.bind("<<ComboboxSelected>>", lambda _: self.refresh_audit())
        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=6)
        self._btn_stop = self._button(bar, "Stop", self.cancel_jobs)
        self._btn_stop.pack(side="left", padx=3)
        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=6)
        self._btn_verify = self._button(bar, "Verify All", self.verify_all)
        self._btn_verify.pack(side="left", padx=3)
        self._btn_verify.config(state="disabled")

        # Summary bar — live counts per result type
        sbar = ttk.Frame(tab)
        sbar.pack(fill="x", padx=8, pady=(2, 0))
        self._summary_labels: Dict[str, ttk.Label] = {}
        for res in ("SUCCESS", "ERROR", "OFFLINE", "BLOCKED", "SKIP"):
            color = {"SUCCESS": "#107c10", "ERROR": "#c50f1f", "OFFLINE": "#c50f1f",
                     "BLOCKED": "#8a6d00", "SKIP": "#555555"}.get(res, "")
            lbl = ttk.Label(sbar, text=f"{res}: 0", foreground=color, font=("Segoe UI", 9, "bold"))
            lbl.pack(side="left", padx=8)
            self._summary_labels[res] = lbl

        self._hint(tab, "Failures shown first. Click column header to sort. Double-click row for full details.")
        cols = ["timestamp", "host", "result", "message", "filename", "target_path",
                "rule_name", "source_type", "version_delta", "backup_path", "verify_status"]
        frame, self.tree_audit = make_tree_hardened(tab, cols, 20)
        frame.pack(fill="both", expand=True)

        # Row color tags
        self.tree_audit.tag_configure("ERROR",   background="#ffdddd")
        self.tree_audit.tag_configure("OFFLINE", background="#ffdddd")
        self.tree_audit.tag_configure("BLOCKED", background="#fff3cd")
        self.tree_audit.tag_configure("SUCCESS", background="#ddffdd")
        self.tree_audit.tag_configure("SKIP",    background="#f0f0f0")

        attach_sort_headers(self.tree_audit, lambda: self.audit, cols, self.refresh_audit)
        self.tree_audit.bind("<Double-1>", self._audit_row_detail)

    def _tab_log(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="6  Log")
        bar = self._toolbar(tab)
        self._button(bar, "Clear log", lambda: self.txt_log.delete("1.0", "end")).pack(side="left", padx=3)
        body = ttk.Frame(tab, padding=(8, 6, 8, 8))
        body.pack(fill="both", expand=True)
        body.rowconfigure(0, weight=1)
        body.columnconfigure(0, weight=1)
        self.txt_log = tk.Text(body, height=18, wrap="none", font=("Consolas", 10))
        y = ttk.Scrollbar(body, orient="vertical", command=self.txt_log.yview)
        x = ttk.Scrollbar(body, orient="horizontal", command=self.txt_log.xview)
        self.txt_log.configure(yscrollcommand=y.set, xscrollcommand=x.set)
        self.txt_log.grid(row=0, column=0, sticky="nsew")
        y.grid(row=0, column=1, sticky="ns")
        x.grid(row=1, column=0, sticky="ew")
        self.txt_log.tag_configure("log_error",   foreground="#c50f1f")
        self.txt_log.tag_configure("log_success", foreground="#107c10")
        self.txt_log.tag_configure("log_warn",    foreground="#8a6d00")

    # ----------------------------- safe UI helpers -----------------------------
    def _set_status(self, prefix: str = "") -> None:
        counts = f"Targets: {len(self.targets)}   Rules: {len(self.rules)}   Inventory: {len(self.inventory)}   Plan: {len(self.plan)}   Audit: {len(self.audit)}"
        self.status_text.set(f"{prefix} | {counts}" if prefix else counts)

    def log(self, msg: str):
        text = f"[{ui_ts()}] {msg}\n"
        if hasattr(self, "txt_log"):
            try:
                upper = msg.upper()
                if any(w in upper for w in ("ERROR", "OFFLINE", "FAIL", "EXCEPTION", "TRACEBACK")):
                    tag = "log_error"
                elif any(w in upper for w in ("SUCCESS", "COMPLETED", "DONE")):
                    tag = "log_success"
                elif any(w in upper for w in ("BLOCKED", "SKIP", "WARN", "CANCEL")):
                    tag = "log_warn"
                else:
                    tag = ""
                self.txt_log.insert("end", text, (tag,) if tag else ())
                line_count = int(self.txt_log.index("end-1c").split(".")[0])
                if line_count > LOG_MAX_LINES:
                    self.txt_log.delete("1.0", f"{line_count - LOG_MAX_LINES}.0")
                self.txt_log.see("end")
            except Exception:
                pass
        if hasattr(self, "status_text"):
            self._set_status(str(msg)[:160])

    def _psexec_valid_or_show(self) -> bool:
        path = self.var_psexec.get().strip() if hasattr(self, "var_psexec") else ""
        if not path or not os.path.isfile(path):
            messagebox.showerror("PsExec required", f"PsExec.exe was not found:\n\n{path or '(blank)'}\n\nSet the correct path before running discovery or execution.")
            return False
        return True


    def import_targets(self):
        """Import host/path CSV using old working two-column logic plus flexible headers.

        Supported examples:
            hostname,path
            TESTPC01,C:\App\bin

            host,bases
            TESTPC01,C:\App\bin;C:\Other\bin

            TESTPC01,C:\App\bin   # no header, old working format
        """
        p = filedialog.askopenfilename(filetypes=[("CSV/TXT", "*.csv *.txt"), ("All", "*.*")])
        if not p:
            return
        try:
            imported, warnings = parse_target_csv_rows(p)
        except Exception as e:
            messagebox.showerror("Target import error", repr(e))
            self.log(f"Target import error: {e!r}")
            return

        if not imported:
            msg = "No targets imported. CSV must include hostname/path, host/bases, or two columns HOST,BASEPATH."
            if warnings:
                msg += "\n\n" + "\n".join(warnings[:10])
            messagebox.showerror("No targets imported", msg)
            return

        # Merge imported bases into existing host entries instead of dropping duplicate host rows.
        existing: Dict[str, Target] = {t.host.lower(): t for t in self.targets}
        added_hosts = 0
        added_bases = 0
        for t in imported:
            key = t.host.lower()
            if key not in existing:
                self.targets.append(Target(t.host, list(t.bases)))
                existing[key] = self.targets[-1]
                added_hosts += 1
                added_bases += len(t.bases)
            else:
                cur = existing[key]
                keys = {b.lower() for b in cur.bases}
                for base in t.bases:
                    if base.lower() not in keys:
                        cur.bases.append(base)
                        keys.add(base.lower())
                        added_bases += 1

        self.refresh_targets()
        self.log(f"Imported targets from {os.path.basename(p)}: hosts added={added_hosts}, base paths added={added_bases}.")
        if warnings:
            self.log("Import warnings: " + " | ".join(warnings[:8]) + (" ..." if len(warnings) > 8 else ""))
            messagebox.showwarning("Imported with warnings", "Imported targets, but some rows were skipped:\n\n" + "\n".join(warnings[:12]))

    # ----------------------------- refresh grids ------------------------------
    def refresh_targets(self):
        self.tree_targets.delete(*self.tree_targets.get_children())
        for idx, t in enumerate(self.targets):
            self.tree_targets.insert("", "end", iid=str(idx), values=[t.host, "; ".join(t.bases)])
        self._set_status()

    def refresh_rules(self):
        self.tree_rules.delete(*self.tree_rules.get_children())
        src_disp  = {i: d for d, i in RuleDialog._SOURCE_TYPES}
        rep_disp  = {i: d for d, i in RuleDialog._REPLACE_WHEN}
        proc_disp = {i: d for d, i in RuleDialog._PROCESS}
        for idx, r in sorted(enumerate(self.rules), key=lambda pair: (pair[1].priority, pair[1].name.lower())):
            tag = "OK" if r.enabled else "SKIP"
            self.tree_rules.insert("", "end", iid=str(idx), values=[
                "✓" if r.enabled else "—",
                r.priority,
                r.name,
                r.filename,
                r.match_family or "(any)",
                src_disp.get(r.source_type, r.source_type),
                r.source_path,
                r.source_file_version,
                rep_disp.get(r.replace_when, r.replace_when),
                proc_disp.get(r.process_handling, r.process_handling),
            ], tags=(tag,))
        self._set_status()

    def refresh_inventory(self):
        self.tree_inventory.delete(*self.tree_inventory.get_children())
        for idx, x in enumerate(self.inventory):
            tag = (x.status or "").upper()
            self.tree_inventory.insert("", "end", iid=str(idx), values=[x.host, x.base, x.filename, x.full_path, x.file_version, x.product_version, x.family, x.company, x.product, x.status, x.message], tags=(tag,))
        self._set_status()

    def refresh_plan(self):
        self.tree_plan.delete(*self.tree_plan.get_children())
        for idx, x in enumerate(self.plan):
            tag = (x.status or "").upper()
            self.tree_plan.insert("", "end", iid=str(idx), values=[x.host, x.filename, x.target_path, x.target_version, x.target_family, x.rule_name, x.source_type, x.source_path, x.source_version, x.source_family, x.status, x.reason], tags=(tag,))
        self._set_status()

    def refresh_audit(self):
        self.tree_audit.delete(*self.tree_audit.get_children())
        filt = getattr(self, "var_audit_filter", None)
        filt_val = filt.get() if filt else "All"
        rows = self.audit if filt_val == "All" else [x for x in self.audit if (x.result or "").upper() == filt_val]
        # Sort by result priority: failures first
        rows = sorted(rows, key=lambda r: RESULT_PRIORITY.get((r.result or "").upper(), 9))
        for idx, x in enumerate(rows):
            tag = (x.result or "").upper()
            self.tree_audit.insert("", "end", iid=str(idx), values=[
                x.timestamp, x.host, x.result, x.message, x.filename,
                x.target_path, x.rule_name, x.source_type,
                _version_delta(x), x.backup_path, x.verify_status,
            ], tags=(tag,))
        suffix = f" ({filt_val})" if filt_val != "All" else ""
        self._set_status(f"Showing {len(rows)}/{len(self.audit)} audit rows{suffix}")
        self._update_summary_bar()

    def _update_summary_bar(self):
        if not hasattr(self, "_summary_labels"):
            return
        counts: Dict[str, int] = {}
        for r in self.audit:
            key = (r.result or "").upper()
            counts[key] = counts.get(key, 0) + 1
        for res, lbl in self._summary_labels.items():
            lbl.config(text=f"{res}: {counts.get(res, 0)}")

    def verify_all(self):
        """Re-read each SUCCESS row's target file via UNC and confirm hash matches source."""
        try:
            self._btn_verify.config(text="Verifying…", state="disabled")
        except Exception:
            pass

        def worker():
            self.uiq.put(("busy", +1))
            try:
                for row in self.audit:
                    if (row.result or "").upper() != "SUCCESS":
                        row.verify_status = "N/A"
                        continue
                    if not row.source_hash:
                        row.verify_status = "N/A"
                        continue
                    try:
                        unc = admin_share_path(row.host, row.target_path)
                        actual = local_sha256(unc)
                        row.verify_status = "VERIFIED" if actual.upper() == row.source_hash.upper() else "MISMATCH"
                    except Exception:
                        row.verify_status = "UNREADABLE"
            finally:
                self.uiq.put(("verify_done",))
                self.uiq.put(("busy", -1))

        threading.Thread(target=worker, daemon=True).start()

    def _audit_row_detail(self, event):
        """Double-click audit row — show full details in a popup."""
        sel = self.tree_audit.focus()
        if not sel:
            return
        try:
            idx = int(sel)
        except (ValueError, TypeError):
            return
        # Find the backing row from the possibly-filtered view by matching iid to audit list
        filt = getattr(self, "var_audit_filter", None)
        filt_val = filt.get() if filt else "All"
        rows = self.audit if filt_val == "All" else [x for x in self.audit if (x.result or "").upper() == filt_val]
        if idx < 0 or idx >= len(rows):
            return
        x = rows[idx]
        lines = [
            f"Host:           {x.host}",
            f"Result:         {x.result}",
            f"Message:        {x.message}",
            f"Filename:       {x.filename}",
            f"Target path:    {x.target_path}",
            f"Rule:           {x.rule_name}",
            f"Source type:    {x.source_type}",
            f"Version:        {_version_delta(x)}",
            f"Verify status:  {x.verify_status or '—'}",
            f"Backup path:    {x.backup_path or '—'}",
            f"Timestamp:      {x.timestamp}",
        ]
        win = tk.Toplevel(self)
        win.title(f"Audit detail — {x.host}")
        win.resizable(True, True)
        txt = tk.Text(win, width=80, height=len(lines) + 2, font=("Consolas", 10), wrap="word")
        txt.pack(fill="both", expand=True, padx=10, pady=8)
        txt.insert("1.0", "\n".join(lines))
        txt.configure(state="disabled")
        ttk.Button(win, text="Close", command=win.destroy).pack(pady=(0, 8))
        win.grab_set()

    # ---------------------- discovery / plan / execute ------------------------
    def fill_discovery_from_rules(self):
        names = sorted({r.filename for r in self.rules if r.enabled and r.filename})
        if not names:
            messagebox.showinfo("Discovery", "No enabled rules with filenames found.")
            return
        text = "\n".join(names)
        self.var_discovery_files.set(text)
        if hasattr(self, "txt_filenames"):
            self.txt_filenames.delete("1.0", "end")
            self.txt_filenames.insert("1.0", text)
        self.nb.select(1)
        self.log(f"Discovery filenames populated from {len(names)} enabled rule(s).")

    def get_discovery_filenames(self) -> List[str]:
        raw = ""
        if hasattr(self, "txt_filenames"):
            try:
                raw = self.txt_filenames.get("1.0", "end").strip()
            except Exception:
                raw = ""
        if not raw and hasattr(self, "var_discovery_files"):
            try:
                raw = self.var_discovery_files.get()
            except Exception:
                raw = ""
        names = split_filename_list(raw)
        if names:
            self.var_discovery_files.set("\n".join(names))
            return names
        return sorted({r.filename for r in self.rules if r.enabled and r.filename})

    def run_discovery(self):
        try:
            if not self.targets:
                messagebox.showerror("Error", "Add targets first.")
                return
            if not self._psexec_valid_or_show():
                return
            filenames = self.get_discovery_filenames()
            if not filenames:
                messagebox.showerror("Error", "Enter one or more filenames to discover, for example: java.exe or javaw.exe.")
                return
            broad = broad_base_paths(self.targets)
            if broad:
                preview = "\n".join(broad[:12])
                if not messagebox.askyesno(
                    "Broad scan base detected",
                    "These imported target base paths are drive roots and may scan a whole drive if Depth is -1:\n\n"
                    + preview
                    + ("\n..." if len(broad) > 12 else "")
                    + "\n\nContinue discovery anyway?",
                ):
                    self.log("Discovery cancelled because broad scan base was detected.")
                    return
            excludes = _parse_excludes(self.var_excludes.get() if hasattr(self, "var_excludes") else ";".join(DEFAULT_EXCLUDES)) or list(DEFAULT_EXCLUDES)
            threads = _int_var_value(self.var_threads, 8, 1, 64)
            depth = _int_var_value(self.var_depth, -1, -1, 50)
            max_results = _int_var_value(self.var_max_results, 200, 1, 10000)

            self.inventory.clear()
            self.refresh_inventory()
            eng = self.get_engine()
            eng.cancel.clear()
            self._busy_jobs += 1
            self.log(f"Discovery started: {len(self.targets)} host(s), filenames={filenames}, threads={threads}, depth={depth}, max/base={max_results}")

            def worker():
                try:
                    target_list = list(self.targets)
                    total_hosts = len(target_list)
                    done_hosts = 0
                    self.uiq.put(("progress", (0, total_hosts)))
                    with ThreadPoolExecutor(max_workers=threads) as pool:
                        futs = [pool.submit(eng.discover_one, t, filenames, depth, excludes, max_results) for t in target_list]
                        for fut in as_completed(futs):
                            if eng.cancel.is_set():
                                break
                            try:
                                for row in fut.result():
                                    if eng.cancel.is_set():
                                        break
                                    self.uiq.put(("inventory", row))
                            except Exception as e:
                                self.uiq.put(("log", f"Discovery worker error: {e!r}"))
                            done_hosts += 1
                            self.uiq.put(("progress", (done_hosts, total_hosts)))
                    self.uiq.put(("log", "Discovery cancelled." if eng.cancel.is_set() else "Discovery completed."))
                finally:
                    self.uiq.put(("busy", -1))
            threading.Thread(target=worker, daemon=True).start()
        except Exception as e:
            self.log(f"Discovery startup error: {e!r}")
            messagebox.showerror("Discovery error", repr(e))

    def build_plan(self):
        try:
            self._progress["value"] = 0
            self.update_idletasks()
            super().build_plan()
            self._progress["value"] = self._progress["maximum"]
            self._set_status(f"Plan built — {len(self.plan)} item(s)")
        except Exception as e:
            self.log(f"Build plan error: {e!r}")
            messagebox.showerror("Build plan error", repr(e))
        finally:
            pass  # progress bar is determinate; no stop() needed

    def execute_plan(self):
        try:
            if not self._psexec_valid_or_show():
                return
            if not self.inventory:
                messagebox.showerror("Error", "Run discovery first.")
                return

            # Auto-rebuild plan so it always reflects current rules + inventory.
            try:
                self._progress["value"] = 0
                self._progress_pct.set("")
                self.update_idletasks()
                super().build_plan()
                self._set_status(f"Plan built — {len(self.plan)} item(s)")
            except Exception as e:
                self.log(f"Plan build error during execute: {e!r}")
                messagebox.showerror("Plan build error", repr(e))
                return

            ok_items = [p for p in self.plan if p.status == "OK"]
            skip_items = [p for p in self.plan if p.status == "SKIP"]
            blocked_items = [p for p in self.plan if p.status == "BLOCKED"]
            offline_items = [p for p in self.plan if p.status == "OFFLINE"]

            lines = [
                f"Plan summary  ({len(self.plan)} total)",
                f"  Replace (OK):  {len(ok_items)}",
                f"  Skip:          {len(skip_items)}",
                f"  Blocked:       {len(blocked_items)}",
                f"  Offline:       {len(offline_items)}",
            ]
            if offline_items:
                lines.append("\nOffline hosts (will NOT execute):")
                for p in offline_items[:8]:
                    lines.append(f"  {p.host}: {p.reason}")
                if len(offline_items) > 8:
                    lines.append(f"  … and {len(offline_items) - 8} more (see Plan tab)")
            if blocked_items:
                lines.append("\nBlocked (will NOT execute — fix rule or source):")
                for p in blocked_items[:8]:
                    lines.append(f"  {p.host} / {p.filename}: {p.reason}")
                if len(blocked_items) > 8:
                    lines.append(f"  … and {len(blocked_items) - 8} more (see Plan tab)")

            if not ok_items:
                messagebox.showinfo("Nothing to execute", "\n".join(lines))
                self.nb.select(3)
                return

            lines.append(f"\nProceed with {len(ok_items)} replacement(s)?")
            if not messagebox.askyesno("Confirm Execute", "\n".join(lines)):
                return
            eng = self.get_engine()
            eng.cancel.clear()
            rule_map = {r.name: r for r in self.rules}
            threads = max(1, min(_int_var_value(self.var_threads, 8, 1, 64), 16))
            self._busy_jobs += 1
            self.nb.select(4)
            self.log(f"Execution started for {len(ok_items)} item(s), threads={threads}")

            def worker():
                try:
                    self._run_items_grouped(ok_items, rule_map, eng, threads, "Execution", "Execution completed.")
                    if not eng.cancel.is_set():
                        self.after(0, lambda: self._btn_verify.config(state="normal") if hasattr(self, "_btn_verify") else None)
                finally:
                    self.uiq.put(("busy", -1))
            threading.Thread(target=worker, daemon=True).start()
        except Exception as e:
            self.log(f"Execution startup error: {e!r}")
            messagebox.showerror("Execution error", repr(e))

    def _run_items_grouped(self, items: list, rule_map: dict, eng, threads: int, log_prefix: str, done_msg: str):
        """Run items in parallel across hosts, but sequentially within each host.

        PsExec can't handle multiple simultaneous connections to the same machine
        reliably — this prevents 'connecting' collisions when a host has many targets.
        """
        from collections import defaultdict
        import threading as _threading
        by_host: dict = defaultdict(list)
        for item in items:
            by_host[item.host].append(item)

        total = len(items)
        counter = {"done": 0}
        lock = _threading.Lock()
        self.uiq.put(("progress", (0, total)))

        def run_one_host(host_items):
            for item in host_items:
                if eng.cancel.is_set():
                    break
                rule = rule_map.get(item.rule_name)
                if not rule:
                    self.uiq.put(("log", f"{log_prefix}: skipped {item.filename} — missing rule '{item.rule_name}'"))
                    with lock:
                        counter["done"] += 1
                        self.uiq.put(("progress", (counter["done"], total)))
                    continue
                try:
                    row = eng.execute_plan_item(item, rule)
                    self.uiq.put(("audit", row))
                except Exception as e:
                    self.uiq.put(("log", f"{log_prefix} worker error ({item.host}): {e!r}"))
                finally:
                    with lock:
                        counter["done"] += 1
                        self.uiq.put(("progress", (counter["done"], total)))

        with ThreadPoolExecutor(max_workers=threads) as pool:
            futs = [pool.submit(run_one_host, host_items) for host_items in by_host.values()]
            for fut in as_completed(futs):
                if eng.cancel.is_set():
                    break
                try:
                    fut.result()
                except Exception as e:
                    self.uiq.put(("log", f"{log_prefix} host error: {e!r}"))

        self.uiq.put(("log", f"{log_prefix} cancelled." if eng.cancel.is_set() else done_msg))

    def cancel_jobs(self):
        try:
            if self.engine:
                self.engine.cancel.set()
                self.engine.runner.kill_all()
            self.log("Cancel requested.")
        except Exception as e:
            self.log(f"Cancel error: {e!r}")

    def retry_failed(self):
        """Re-execute OK plan items for hosts that have ERROR or OFFLINE audit results."""
        try:
            if not self._psexec_valid_or_show():
                return
            failed_hosts = {r.host for r in self.audit if r.result in ("ERROR", "OFFLINE")}
            if not failed_hosts:
                messagebox.showinfo("Retry failed", "No ERROR or OFFLINE results in audit.")
                return
            retry_items = [p for p in self.plan if p.status == "OK" and p.host in failed_hosts]
            if not retry_items:
                messagebox.showinfo("Retry failed", "No OK plan items found for the failed hosts.")
                return
            if not messagebox.askyesno("Confirm retry", f"Re-execute {len(retry_items)} item(s) for {len(failed_hosts)} failed host(s)?"):
                return
            eng = self.get_engine()
            eng.cancel.clear()
            rule_map = {r.name: r for r in self.rules}
            threads = max(1, min(_int_var_value(self.var_threads, 8, 1, 64), 16))
            self._busy_jobs += 1
            self.log(f"Retry started: {len(retry_items)} item(s) on {len(failed_hosts)} host(s), threads={threads}")

            def worker():
                try:
                    self._run_items_grouped(retry_items, rule_map, eng, threads, "Retry", "Retry completed.")
                    if not eng.cancel.is_set():
                        self.after(0, lambda: self._btn_verify.config(state="normal") if hasattr(self, "_btn_verify") else None)
                finally:
                    self.uiq.put(("busy", -1))
            threading.Thread(target=worker, daemon=True).start()
        except Exception as e:
            self.log(f"Retry startup error: {e!r}")
            messagebox.showerror("Retry error", repr(e))

    def save_targets(self):
        """Save current targets to a CSV file for later reload via Import CSV/TXT."""
        if not self.targets:
            messagebox.showinfo("Save targets", "No targets to save.")
            return
        p = filedialog.asksaveasfilename(
            defaultextension=".csv", initialfile="targets.csv",
            filetypes=[("CSV", "*.csv"), ("All files", "*.*")],
        )
        if not p:
            return
        try:
            with open(p, "w", newline="", encoding="utf-8-sig") as fh:
                w = csv.writer(fh)
                w.writerow(["host", "bases"])
                for t in self.targets:
                    w.writerow([t.host, ";".join(t.bases)])
            self.log(f"Saved {len(self.targets)} target(s) to {os.path.basename(p)}")
        except Exception as e:
            self.log(f"Save targets error: {e!r}")
            messagebox.showerror("Save targets error", repr(e))

    def export_inventory_report(self):
        """Export a focused 3-column report: hostname, file path, family group."""
        found = [x for x in self.inventory if x.status == "FOUND"]
        if not found:
            messagebox.showinfo("Export Report", "No FOUND inventory rows to export.")
            return
        p = filedialog.asksaveasfilename(
            defaultextension=".csv", initialfile="inventory_report.csv",
            filetypes=[("CSV", "*.csv"), ("All files", "*.*")],
        )
        if not p:
            return
        try:
            with open(p, "w", newline="", encoding="utf-8-sig") as fh:
                w = csv.writer(fh)
                w.writerow(["Hostname", "File Path", "Family Group"])
                for x in found:
                    label = friendly_family(x.filename, x.family, x.product, x.company)
                    w.writerow([x.host, x.full_path, label])
            self.log(f"Inventory report exported: {len(found)} row(s) to {os.path.basename(p)}")
        except Exception as e:
            self.log(f"Export report error: {e!r}")
            messagebox.showerror("Export error", repr(e))

    def export_inventory_excel(self):
        """Export inventory to Excel: one sheet per Java family, javaw.exe before java.exe, sorted by host."""
        try:
            import openpyxl
            from openpyxl.styles import Font, PatternFill, Alignment
        except ImportError:
            messagebox.showerror(
                "Missing library",
                "openpyxl is required for Excel export.\n\nInstall it with:\n    pip install openpyxl",
            )
            return

        found = [x for x in self.inventory if x.status == "FOUND"]
        if not found:
            messagebox.showinfo("Export Excel", "No FOUND inventory rows to export.")
            return

        p = filedialog.asksaveasfilename(
            defaultextension=".xlsx",
            initialfile="inventory_report.xlsx",
            filetypes=[("Excel workbook", "*.xlsx"), ("All files", "*.*")],
        )
        if not p:
            return

        try:
            from collections import defaultdict
            by_family: Dict[str, list] = defaultdict(list)
            for x in found:
                fam = (x.family or "").strip()
                by_family[fam].append(x)

            # Sort rows within each family: javaw.exe first, then java.exe, then alphabetical; then by host
            def _row_sort(x):
                name = (x.filename or "").lower()
                return (0 if name.startswith("javaw") else 1, name, (x.host or "").lower())

            for rows in by_family.values():
                rows.sort(key=_row_sort)

            # Sort families numerically where possible (8 < 11 < 17 ...), then unknown last
            def _fam_key(f):
                try:
                    return (0, int(f))
                except (ValueError, TypeError):
                    return (1, f or "")

            sorted_families = sorted(by_family.keys(), key=_fam_key)

            wb = openpyxl.Workbook()
            wb.remove(wb.active)  # remove auto-created blank sheet

            HDR_FONT  = Font(bold=True, color="FFFFFF")
            HDR_FILL  = PatternFill(fill_type="solid", fgColor="2E75B6")
            HDR_ALIGN = Alignment(horizontal="center")

            columns  = ["Host", "Filename", "File Path", "File Version", "Product Version", "Company"]
            col_widths = [26,      12,          60,           14,             14,               22]

            for fam in sorted_families:
                sheet_name = f"Java {fam}" if fam else "Unknown"
                sheet_name = sheet_name[:31]  # Excel sheet name limit
                ws = wb.create_sheet(title=sheet_name)
                ws.freeze_panes = "A2"

                for ci, (col, width) in enumerate(zip(columns, col_widths), 1):
                    cell = ws.cell(row=1, column=ci, value=col)
                    cell.font  = HDR_FONT
                    cell.fill  = HDR_FILL
                    cell.alignment = HDR_ALIGN
                    ws.column_dimensions[cell.column_letter].width = width

                for ri, x in enumerate(by_family[fam], 2):
                    ws.cell(ri, 1, x.host)
                    ws.cell(ri, 2, x.filename)
                    ws.cell(ri, 3, x.full_path)
                    ws.cell(ri, 4, x.file_version)
                    ws.cell(ri, 5, x.product_version)
                    ws.cell(ri, 6, x.company)

            wb.save(p)
            total = len(found)
            self.log(f"Excel export: {total} rows, {len(sorted_families)} sheets → {os.path.basename(p)}")
            messagebox.showinfo(
                "Export complete",
                f"Exported {total} findings across {len(sorted_families)} sheets.\n\n{p}",
            )
        except Exception as e:
            self.log(f"Excel export error: {e!r}")
            messagebox.showerror("Export error", repr(e))

    # ----------------------------- import/export ------------------------------
    def export_csv(self, rows_or_scope, default_name: Optional[str] = None):
        if isinstance(rows_or_scope, str):
            scope = rows_or_scope.lower()
            if scope == "inventory":
                rows, default_name = self.inventory, default_name or "inventory.csv"
            elif scope == "plan":
                rows, default_name = self.plan, default_name or "plan.csv"
            elif scope == "audit":
                rows, default_name = self.audit, default_name or "audit.csv"
            else:
                messagebox.showerror("Export", f"Unknown export scope: {rows_or_scope}")
                return
        else:
            rows = rows_or_scope
            default_name = default_name or "export.csv"
        if not rows:
            messagebox.showinfo("Export", "No rows to export.")
            return
        p = filedialog.asksaveasfilename(defaultextension=".csv", initialfile=default_name, filetypes=[("CSV", "*.csv"), ("All files", "*.*")])
        if not p:
            return
        try:
            with open(p, "w", newline="", encoding="utf-8-sig") as f:
                w = csv.DictWriter(f, fieldnames=list(asdict(rows[0]).keys()))
                w.writeheader()
                for r in rows:
                    w.writerow(asdict(r))
            self.log(f"Exported {len(rows)} rows to {p}")
        except Exception as e:
            self.log(f"Export error: {e!r}")
            messagebox.showerror("Export error", repr(e))

    # ------------------------------- queue pump -------------------------------
    def _pump(self):
        try:
            while True:
                kind, data = self.uiq.get_nowait()
                if kind == "inventory":
                    # Direct insert instead of full grid rebuild (O(1) vs O(n²)).
                    self.inventory.append(data)
                    x = data
                    tag = (x.status or "").upper()
                    idx = len(self.inventory) - 1
                    try:
                        self.tree_inventory.insert(
                            "", "end", iid=str(idx),
                            values=[x.host, x.base, x.filename, x.full_path,
                                    x.file_version, x.product_version, x.family,
                                    x.company, x.product, x.status, x.message],
                            tags=(tag,),
                        )
                    except Exception:
                        pass
                    self._set_status()
                elif kind == "audit":
                    # Direct insert instead of full grid rebuild (O(1) vs O(n²)).
                    self.audit.append(data)
                    x = data
                    tag = (x.result or "").upper()
                    # Surface errors and offline results in the log so they're impossible to miss.
                    if tag in ("ERROR", "OFFLINE", "BLOCKED"):
                        self.log(f"{tag} [{x.host}] {x.filename}: {x.message}")
                    filt = getattr(self, "var_audit_filter", None)
                    filt_val = filt.get() if filt else "All"
                    if filt_val == "All" or tag == filt_val:
                        idx = len(self.audit) - 1
                        try:
                            self.tree_audit.insert(
                                "", "end", iid=str(idx),
                                values=[x.timestamp, x.host, x.result, x.message,
                                        x.filename, x.target_path, x.rule_name,
                                        x.source_type, _version_delta(x),
                                        x.backup_path, x.verify_status],
                                tags=(tag,),
                            )
                        except Exception:
                            pass
                    self._set_status()
                    self._update_summary_bar()
                elif kind == "verify_done":
                    self.refresh_audit()
                    try:
                        self._btn_verify.config(text="Re-Verify", state="normal")
                    except Exception:
                        pass
                elif kind == "log":
                    self.log(str(data))
                elif kind == "progress":
                    done, total = data
                    try:
                        if total > 0:
                            self._progress["maximum"] = total
                            self._progress["value"] = done
                            pct = int(done / total * 100)
                            self._progress_pct.set(f"{pct}%")
                        else:
                            self._progress["value"] = 0
                            self._progress_pct.set("")
                    except Exception:
                        pass
                elif kind == "busy":
                    was_busy = self._busy_jobs > 0
                    try:
                        self._busy_jobs = max(0, self._busy_jobs + int(data))
                    except Exception:
                        self._busy_jobs = 0
                    now_busy = self._busy_jobs > 0
                    if not was_busy and now_busy:
                        try:
                            self._progress.stop()
                            self._progress["value"] = 0
                            self._progress["maximum"] = 100
                            self._progress_pct.set("")
                        except Exception:
                            pass
                    elif was_busy and not now_busy:
                        try:
                            self._progress.stop()
                            self._progress["value"] = self._progress["maximum"]
                            self._progress_pct.set("100%")
                        except Exception:
                            pass
                    self._set_status("Working..." if self._busy_jobs else "Ready")
        except queue.Empty:
            pass
        except Exception as e:
            # Never let a UI queue item kill the Tk loop.
            try:
                self.log(f"UI pump error: {e!r}")
            except Exception:
                pass
        self.after(150, self._pump)



if __name__ == "__main__":
    HardenedApp().mainloop()
