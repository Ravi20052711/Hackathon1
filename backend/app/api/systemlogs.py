"""
SYSTEM LOG READER - Fixed version
"""

from fastapi import APIRouter
import subprocess
import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)
router = APIRouter()


def run_powershell(command: str):
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True, text=True, timeout=25
        )
        stderr = result.stderr.strip()
        stdout = result.stdout.strip()

        if stderr:
            logger.warning(f"PS stderr: {stderr}")
        if not stdout:
            logger.error("PS returned empty output")
            return [], f"Empty output. stderr: {stderr}"

        data = json.loads(stdout)
        if isinstance(data, dict):
            data = [data]
        return data, None

    except json.JSONDecodeError as e:
        logger.error(f"JSON parse error: {e} | stdout: {result.stdout[:300]}")
        return [], f"JSON parse error: {str(e)}"
    except Exception as e:
        logger.error(f"PowerShell error: {e}")
        return [], str(e)


def parse_entry(entry: dict, log_name: str) -> dict:
    # EntryType can be int or string depending on PS version
    entry_type = entry.get("EntryType", 0)

    # Map numeric EntryType values
    numeric_map = {
        1: "ERROR",
        2: "WARNING",
        4: "INFO",
        8: "DEBUG",
        16: "CRITICAL",
    }
    string_map = {
        "Error": "ERROR",
        "Warning": "WARNING",
        "Information": "INFO",
        "FailureAudit": "CRITICAL",
        "SuccessAudit": "DEBUG",
    }

    if isinstance(entry_type, int):
        level = numeric_map.get(entry_type, "INFO")
    elif isinstance(entry_type, dict):
        # PS sometimes returns {"value__": 4} format
        val = entry_type.get("value__", 4)
        level = numeric_map.get(val, "INFO")
    else:
        level = string_map.get(str(entry_type), "INFO")

    # TimeGenerated can be a string or dict
    ts = entry.get("TimeGenerated", "")
    if isinstance(ts, dict):
        ts = ts.get("DateTime", str(ts))

    source = str(entry.get("Source", ""))
    message = str(entry.get("Message", "") or "")
    message = message[:400].replace("\r\n", " ").replace("\n", " ").strip()
    event_id = str(entry.get("EventID", ""))

    return {
        "timestamp": ts,
        "level": level,
        "source": source,
        "message": f"{source}: {message}" if source else message,
        "raw": f"[{ts}] [{level}] [EventID:{event_id}] [{log_name}] {source}: {message}",
        "event_id": event_id,
        "log_name": log_name,
    }


def fetch_event_log(log_name: str, limit: int):
    # Use -ExpandProperty to get clean string for EntryType
    cmd = f"""
$entries = Get-EventLog -LogName '{log_name}' -Newest {limit} -ErrorAction Stop
$entries | ForEach-Object {{
    [PSCustomObject]@{{
        TimeGenerated = $_.TimeGenerated.ToString('yyyy-MM-dd HH:mm:ss')
        EntryType     = $_.EntryType.ToString()
        Source        = $_.Source
        EventID       = $_.EventID
        Message       = ($_.Message -replace '`n',' ' -replace '`r',' ')[0..399] -join ''
    }}
}} | ConvertTo-Json -Depth 2
"""
    return run_powershell(cmd)


@router.get("/windows")
async def get_windows_logs(log_name: str = "System", limit: int = 80):
    raw, err = fetch_event_log(log_name, limit)
    if err and not raw:
        return {"logs": [], "error": err, "source": log_name, "count": 0}
    logs = [parse_entry(e, log_name) for e in raw]
    return {
        "logs": logs,
        "source": f"Windows {log_name} Event Log",
        "count": len(logs),
        "timestamp": datetime.now().isoformat()
    }


@router.get("/application")
async def get_application_logs(limit: int = 80):
    return await get_windows_logs("Application", limit)


@router.get("/security")
async def get_security_logs(limit: int = 80):
    return await get_windows_logs("Security", limit)


@router.get("/test")
async def test_connection():
    """Quick test endpoint — check if Windows log reading works."""
    raw, err = fetch_event_log("System", 3)
    return {
        "success": len(raw) > 0,
        "entries_found": len(raw),
        "error": err,
        "sample": raw[0] if raw else None
    }