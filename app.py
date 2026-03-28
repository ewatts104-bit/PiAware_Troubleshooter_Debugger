#!/usr/bin/env python3
"""
PiAware RTL-SDR Troubleshooter
Flask 3.x + Flask-SocketIO + eventlet — port 8080

Run: python app.py
Prod: gunicorn --worker-class eventlet -w 1 -b 0.0.0.0:8080 app:app
"""

import eventlet
eventlet.monkey_patch()

import os
import re
import pty
import select
import signal
import subprocess
import threading
import time
import json
import logging
import struct
import fcntl
import termios
from pathlib import Path
from datetime import datetime

import psutil
from flask import Flask, render_template, jsonify, request, Response, stream_with_context
from flask_socketio import SocketIO, emit
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ─── Structured logging ────────────────────────────────────────────────────────
class JSONFormatter(logging.Formatter):
    def format(self, record):
        return json.dumps({
            "ts": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        })

handler = logging.StreamHandler()
handler.setFormatter(JSONFormatter())
logging.basicConfig(level=logging.INFO, handlers=[handler])
log = logging.getLogger("piaware-troubleshooter")

# ─── App ───────────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(32)

socketio = SocketIO(
    app,
    async_mode="eventlet",
    cors_allowed_origins="*",
    ping_timeout=60,
    ping_interval=25,
)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["300 per minute"],
    storage_uri="memory://",
)

# ─── Config ────────────────────────────────────────────────────────────────────
PORT = int(os.environ.get("PORT", 8081))

LOG_FILES = {
    "piaware":  "/var/log/piaware.log",
    "dump1090": "/run/dump1090-fa/output.log",
    "syslog":   "/var/log/syslog",
    "messages": "/var/log/messages",
}

CONFIG_FILES = {
    "piaware":  "/etc/piaware.conf",
    "dump1090": "/etc/default/dump1090-fa",
}

# Persistent gain config — survives reboot (unlike /etc/default/ which is regenerated)
PIAWARE_CONFIG_PATHS = [
    "/boot/piaware-config.txt",
    "/boot/firmware/piaware-config.txt",
]

# Standard RTL2838 gain table (dB)
GAIN_VALUES = [
    0.0, 0.9, 1.4, 2.7, 3.7, 7.7, 8.7, 12.5, 14.4, 15.7,
    16.6, 19.7, 20.7, 22.9, 25.4, 28.0, 29.7, 32.8, 33.8,
    36.4, 37.2, 38.6, 40.2, 42.1, 43.4, 43.9, 44.5, 48.0, 49.6,
]
GAIN_SPECIAL = {"max", "auto"}  # piaware also accepts these

STATS_PATHS = [
    "/run/dump1090-fa/stats.json",
    "/tmp/dump1090-fa/stats.json",
    "/var/run/dump1090-fa/stats.json",
    "/run/readsb/stats.json",
]

# ─── Whitelist patterns for custom console input ───────────────────────────────
SAFE_PATTERNS = [
    r"^lsusb(\s+(-[vVt]|--verbose|--tree))*$",
    r"^dmesg(\s+--color=never)?(\s*\|\s*grep\s+-[Ei]?\s*'?[\w\|\-\.\s]+'?)?$",
    r"^sudo\s+dmesg(\s+--color=never)?(\s*\|\s*grep\s+-[Ei]?\s*'?[\w\|\-\.\s]+'?)?$",
    r"^lsmod(\s*\|\s*grep\s+[\w]+)?$",
    r"^rtl_test(\s+[-\w\s\.]+)?$",
    r"^sudo\s+rtl_test(\s+[-\w\s\.]+)?$",
    r"^rtl_eeprom(\s+[-\w\s]+)?$",
    r"^sudo\s+rtl_eeprom(\s+[-\w\s]+)?$",
    r"^systemctl\s+(status|restart|stop|start|is-active|is-enabled)\s+(piaware|dump1090-fa|readsb)$",
    r"^sudo\s+systemctl\s+(restart|stop|start)\s+(piaware|dump1090-fa|readsb)$",
    r"^journalctl\s+-u\s+(piaware|dump1090-fa|readsb)(\s+[-\w\s=]+)?$",
    r"^vcgencmd\s+(measure_temp|get_throttled|measure_clock\s+\w+|measure_volts(\s+\w+)?)$",
    r"^cat\s+(/etc/piaware\.conf|/etc/default/dump1090-fa|/proc/asound/cards|/proc/cpuinfo|/proc/meminfo|/proc/bus/usb/devices)$",
    r"^sudo\s+usb-devices$",
    r"^usb-devices$",
    r"^ip\s+(addr|link|route)(\s+\w+)?$",
    r"^ss\s+[-tlnp]+$",
    r"^netstat\s+[-tlnp]+$",
    r"^free(\s+[-h])?$",
    r"^df(\s+[-h])?$",
    r"^uptime$",
    r"^uname(\s+[-asr])?$",
    r"^ps\s+(aux|axf)(\s*\|\s*grep\s+[\w\-\.]+)?$",
    r"^ping\s+-c\s+\d{1,3}\s+[\w\.\-]+$",
    r"^tail\s+-n\s+\d+\s+[\w/\.\-]+$",
    r"^ls\s+[-lah]+(\s+[\w/\.\-]+)?$",
    r"^find\s+[\w/\.\-]+(\s+[-\w\s\.\*]+)?$",
    r"^grep\s+-[rwilEnH]+\s+[\w\.\-'\"]+\s+[\w/\.\-]+$",
    r"^sudo\s+grep\s+-[rwilEnH]+\s+[\w\.\-'\"]+\s+[\w/\.\-]+$",
    r"^tcpdump\s+-i\s+\w+\s+port\s+\d{1,5}(\s+-c\s+\d+)?(\s+-n)?$",
    r"^sudo\s+tcpdump\s+-i\s+\w+\s+port\s+\d{1,5}(\s+-c\s+\d+)?(\s+-n)?$",
    r"^iwconfig(\s+\w+)?$",
    r"^ifconfig(\s+[\w\.\-]+)?$",
    r"^arp(\s+-[an])?$",
    r"^nmap\s+-p\s+[\d,\-]+\s+[\w\.\-/]+$",
    r"^modprobe(\s+[-r])?\s+[\w\-]+$",
    r"^sudo\s+modprobe(\s+[-r])?\s+[\w\-]+$",
    r"^rmmod\s+[\w\-]+$",
    r"^sudo\s+rmmod\s+[\w\-]+$",
    r"^vcdbg\s+log\s+msg$",
    r"^clear$",
    r"^history$",
    r"^pwd$",
    r"^whoami$",
    r"^id$",
    r"^date$",
    r"^env$",
    r"^printenv(\s+\w+)?$",
]

_safe_compiled = [re.compile(p, re.IGNORECASE) for p in SAFE_PATTERNS]

def is_safe_command(cmd: str) -> bool:
    cmd = cmd.strip()
    for pattern in _safe_compiled:
        if pattern.fullmatch(cmd):
            return True
    return False

# ─── System status helpers ─────────────────────────────────────────────────────

def run_cmd(cmd: list, timeout: int = 10) -> tuple:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout + r.stderr).strip()
    except subprocess.TimeoutExpired:
        return -1, f"[TIMEOUT {timeout}s]"
    except FileNotFoundError:
        return -1, f"[not found: {cmd[0]}]"
    except Exception as e:
        return -1, f"[error: {e}]"


def get_rtlsdr_status() -> dict:
    rc, out = run_cmd(["lsusb"])
    patterns = ["0bda:2838", "0bda:2832", "0bda:2837", "rtl2838", "rtl2832", "realtek semiconductor"]
    device_line = ""
    detected = False
    for line in out.splitlines():
        if any(p in line.lower() for p in patterns):
            detected = True
            device_line = line.strip()
            break
    return {
        "detected": detected,
        "device": device_line or "Not found",
        "status": "ok" if detected else "error",
    }


def get_service_status(service: str) -> dict:
    rc1, active = run_cmd(["systemctl", "is-active", service])
    rc2, enabled = run_cmd(["systemctl", "is-enabled", service])
    is_active = active.strip() == "active"
    is_enabled = enabled.strip() in ("enabled", "enabled-runtime")
    return {
        "active": is_active,
        "enabled": is_enabled,
        "state": active.strip(),
        "status": "ok" if is_active else "error",
    }


def get_cpu_temp() -> dict:
    rc, out = run_cmd(["vcgencmd", "measure_temp"])
    if rc == 0:
        m = re.search(r"temp=([\d.]+)", out)
        if m:
            temp = float(m.group(1))
            return {
                "celsius": temp,
                "fahrenheit": round(temp * 9 / 5 + 32, 1),
                "status": "ok" if temp < 70 else ("warn" if temp < 80 else "error"),
            }
    try:
        with open("/sys/class/thermal/thermal_zone0/temp") as f:
            temp = int(f.read().strip()) / 1000
            return {
                "celsius": temp,
                "fahrenheit": round(temp * 9 / 5 + 32, 1),
                "status": "ok" if temp < 70 else ("warn" if temp < 80 else "error"),
            }
    except Exception:
        return {"celsius": 0, "fahrenheit": 0, "status": "unknown"}


def get_throttle_status() -> dict:
    rc, out = run_cmd(["vcgencmd", "get_throttled"])
    if rc == 0:
        m = re.search(r"throttled=0x([0-9a-fA-F]+)", out)
        if m:
            val = int(m.group(1), 16)
            flags = []
            bit_map = {
                0x00001: "Under-voltage detected",
                0x00002: "Arm freq capped",
                0x00004: "Currently throttled",
                0x00008: "Soft temp limit active",
                0x10000: "Under-voltage occurred",
                0x20000: "Arm freq cap occurred",
                0x40000: "Throttling occurred",
                0x80000: "Soft temp limit occurred",
            }
            for bit, label in bit_map.items():
                if val & bit:
                    flags.append(label)
            return {
                "raw": hex(val),
                "flags": flags,
                "ok": val == 0,
                "status": "ok" if val == 0 else ("warn" if not (val & 0x4) else "error"),
            }
    return {"raw": "n/a", "flags": [], "ok": True, "status": "unknown"}


def get_dump1090_stats() -> dict:
    for path in STATS_PATHS:
        try:
            with open(path) as f:
                data = json.load(f)
            last = data.get("last1min", data.get("total", {}))
            local = last.get("local", {})
            return {
                "messages": last.get("messages", 0),
                "aircraft": last.get("unique_aircraft", 0),
                "strong_signals": local.get("strong_signals", 0),
                "signal_dbfs": round(local.get("signal", 0), 1),
                "noise_dbfs": round(local.get("noise", 0), 1),
                "peak_signal_dbfs": round(local.get("peak_signal", 0), 1),
                "status": "ok",
                "source": path,
            }
        except Exception:
            continue
    return {"messages": 0, "aircraft": 0, "status": "unknown", "source": "none"}


def get_system_resources() -> dict:
    try:
        cpu = psutil.cpu_percent(interval=0.2)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        temps = {}
        try:
            t = psutil.sensors_temperatures()
            if t:
                for k, v in t.items():
                    if v:
                        temps[k] = v[0].current
        except Exception:
            pass
        return {
            "cpu_percent": cpu,
            "cpu_count": psutil.cpu_count(),
            "mem_percent": mem.percent,
            "mem_used_mb": mem.used // (1024 * 1024),
            "mem_total_mb": mem.total // (1024 * 1024),
            "disk_percent": disk.percent,
            "disk_free_gb": round(disk.free / (1024 ** 3), 1),
            "load_avg": list(os.getloadavg()),
            "temps": temps,
        }
    except Exception as e:
        return {"error": str(e)}


def _piaware_config_path() -> str:
    for p in PIAWARE_CONFIG_PATHS:
        if os.path.exists(p):
            return p
    return PIAWARE_CONFIG_PATHS[0]


def _read_piaware_config() -> str:
    with open(_piaware_config_path()) as f:
        return f.read()


def get_gain_1090() -> str:
    try:
        m = re.search(r"^rtlsdr-gain\s+([\d.]+|max|auto)", _read_piaware_config(), re.MULTILINE | re.IGNORECASE)
        return m.group(1) if m else "unknown"
    except Exception:
        return "unknown"


def get_gain_978() -> str:
    try:
        m = re.search(r"uat-sdr-device\s+[^\n]*?,gain=([\d.]+|max|auto)", _read_piaware_config(), re.IGNORECASE)
        return m.group(1) if m else "unknown"
    except Exception:
        return "unknown"


def _validate_gain(val: str) -> bool:
    if val.lower() in GAIN_SPECIAL:
        return True
    try:
        return float(val) in GAIN_VALUES
    except ValueError:
        return False


def _boot_mount_point() -> str | None:
    """Return the mount point of the FAT boot partition if it's not /boot directly."""
    for candidate in ["/boot/firmware", "/boot"]:
        if os.path.exists(os.path.join(candidate, "piaware-config.txt")):
            # Check if it's a separate vfat mount (i.e. can be remounted)
            try:
                with open("/proc/mounts") as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) >= 3 and parts[1] == candidate and parts[2] == "vfat":
                            return candidate
            except Exception:
                pass
    return None


def _write_piaware_config(content: str) -> tuple:
    """Write content to piaware-config.txt, remounting the boot FAT partition rw/ro as needed."""
    path = _piaware_config_path()
    mount_point = _boot_mount_point()

    if mount_point:
        # Remount rw
        r = subprocess.run(["sudo", "mount", "-o", "remount,rw", mount_point],
                           capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            return False, f"remount rw failed: {r.stderr.strip()}"

    try:
        proc = subprocess.run(["sudo", "tee", path], input=content,
                              capture_output=True, text=True, timeout=10)
        ok = proc.returncode == 0
        err = proc.stderr.strip()
    finally:
        if mount_point:
            subprocess.run(["sudo", "mount", "-o", "remount,ro", mount_point],
                           capture_output=True, text=True, timeout=10)

    return ok, err


def set_gain_1090(gain: str) -> tuple:
    try:
        content = _read_piaware_config()
    except Exception as e:
        return False, str(e)
    new = re.sub(
        r"^(rtlsdr-gain\s+)(?:[\d.]+|max|auto)(\s+#.*)?$",
        f"rtlsdr-gain {gain}   # updated by piaware-troubleshooter",
        content,
        flags=re.MULTILINE | re.IGNORECASE,
    )
    if new == content:
        return False, "rtlsdr-gain line not found in piaware-config.txt"
    return _write_piaware_config(new)


def set_gain_978(gain: str) -> tuple:
    try:
        content = _read_piaware_config()
    except Exception as e:
        return False, str(e)
    new = re.sub(
        r"(uat-sdr-device\s+[^\n]*?,gain=)(?:[\d.]+|max|auto)",
        f"\\g<1>{gain}",
        content,
        flags=re.IGNORECASE,
    )
    if new == content:
        return False, "uat-sdr-device gain not found in piaware-config.txt"
    return _write_piaware_config(new)


# kept for backward compat with status endpoint
def get_piaware_gain() -> str:
    return get_gain_1090()


# ─── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/status")
@limiter.limit("60 per minute")
def api_status():
    return jsonify({
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "rtlsdr": get_rtlsdr_status(),
        "piaware": get_service_status("piaware"),
        "dump1090": get_service_status("dump1090-fa"),
        "dump978": get_service_status("dump978-fa"),
        "temp": get_cpu_temp(),
        "throttle": get_throttle_status(),
        "dump1090_stats": get_dump1090_stats(),
        "resources": get_system_resources(),
        "gain": get_piaware_gain(),
        "gain_1090": get_gain_1090(),
        "gain_978": get_gain_978(),
    })


@app.route("/api/gain/<dongle>")
@limiter.limit("30 per minute")
def api_gain_get(dongle):
    if dongle == "1090":
        return jsonify({"gain": get_gain_1090(), "dongle": "1090", "values": GAIN_VALUES})
    if dongle == "978":
        return jsonify({"gain": get_gain_978(), "dongle": "978", "values": GAIN_VALUES})
    return jsonify({"error": "unknown dongle"}), 400


@app.route("/api/gain/<dongle>", methods=["POST"])
@limiter.limit("10 per minute")
def api_gain_set(dongle):
    if dongle not in ("1090", "978"):
        return jsonify({"error": "unknown dongle"}), 400
    data = request.get_json(silent=True)
    if not data or "gain" not in data:
        return jsonify({"error": "missing gain"}), 400
    gain = str(data["gain"]).strip().lower()
    if not _validate_gain(gain):
        return jsonify({"error": f"invalid gain '{gain}' — must be one of the RTL2838 gain steps or 'max'/'auto'"}), 400

    if dongle == "1090":
        ok, err = set_gain_1090(gain)
        service = "dump1090-fa"
    else:
        ok, err = set_gain_978(gain)
        service = "dump978-fa"

    if not ok:
        return jsonify({"error": err or "config write failed"}), 500

    rc, svc_out = run_cmd(["sudo", "systemctl", "restart", service], 30)
    log.info({"action": "gain_set", "dongle": dongle, "gain": gain, "service_rc": rc})
    return jsonify({"ok": True, "gain": gain, "dongle": dongle, "service_restart_rc": rc, "service_out": svc_out})


@app.route("/api/logs/<logname>")
@limiter.limit("20 per minute")
def api_log_tail(logname):
    if logname not in LOG_FILES:
        return jsonify({"error": "unknown log"}), 400
    path = LOG_FILES[logname]
    rc, out = run_cmd(["tail", "-n", "300", path])
    if rc != 0 and not out:
        return jsonify({"error": f"Cannot read {path}", "lines": []}), 200
    return jsonify({"lines": out.splitlines(), "path": path})


@app.route("/api/logs/<logname>/stream")
def api_log_stream(logname):
    if logname not in LOG_FILES:
        return jsonify({"error": "unknown log"}), 400
    path = LOG_FILES[logname]

    def generate():
        try:
            proc = subprocess.Popen(
                ["tail", "-F", "-n", "50", path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            try:
                for line in proc.stdout:
                    yield f"data: {json.dumps({'line': line.rstrip()})}\n\n"
                    eventlet.sleep(0)
            finally:
                proc.terminate()
                proc.wait()
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"

    return Response(
        stream_with_context(generate()),
        content_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/api/journal/<service>/stream")
def api_journal_stream(service):
    if service not in ("piaware", "dump1090-fa", "dump978-fa", "readsb"):
        return jsonify({"error": "unknown service"}), 400

    def generate():
        try:
            proc = subprocess.Popen(
                ["journalctl", "-u", service, "-f", "-n", "50",
                 "--no-pager", "--output=short-iso"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            try:
                for line in proc.stdout:
                    yield f"data: {json.dumps({'line': line.rstrip()})}\n\n"
                    eventlet.sleep(0)
            finally:
                proc.terminate()
                proc.wait()
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"

    return Response(
        stream_with_context(generate()),
        content_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/api/config/<cfgname>")
@limiter.limit("30 per minute")
def api_config_read(cfgname):
    if cfgname not in CONFIG_FILES:
        return jsonify({"error": "unknown config"}), 400
    path = CONFIG_FILES[cfgname]
    try:
        with open(path) as f:
            content = f.read()
        return jsonify({"content": content, "path": path})
    except PermissionError:
        return jsonify({"error": f"Permission denied: {path}"}), 403
    except FileNotFoundError:
        return jsonify({"error": f"Not found: {path}", "content": "", "path": path})


@app.route("/api/config/<cfgname>", methods=["POST"])
@limiter.limit("5 per minute")
def api_config_write(cfgname):
    if cfgname not in CONFIG_FILES:
        return jsonify({"error": "unknown config"}), 400
    path = CONFIG_FILES[cfgname]
    data = request.get_json(silent=True)
    if not data or "content" not in data:
        return jsonify({"error": "no content"}), 400
    content = data["content"]
    if "\x00" in content or len(content) > 131072:
        return jsonify({"error": "invalid content"}), 400
    try:
        proc = subprocess.run(
            ["sudo", "tee", path],
            input=content,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if proc.returncode != 0:
            return jsonify({"error": proc.stderr or "sudo tee failed"}), 500
        log.info({"action": "config_write", "path": path})
        return jsonify({"ok": True, "path": path})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/service/<service>/<action>", methods=["POST"])
@limiter.limit("10 per minute")
def api_service_action(service, action):
    if service not in ("piaware", "dump1090-fa", "dump978-fa", "readsb"):
        return jsonify({"error": "unknown service"}), 400
    if action not in ("restart", "stop", "start"):
        return jsonify({"error": "unknown action"}), 400
    rc, out = run_cmd(["sudo", "systemctl", action, service], timeout=30)
    log.info({"action": f"service_{action}", "service": service, "rc": rc})
    return jsonify({"ok": rc == 0, "output": out, "rc": rc})


@app.route("/api/toolkit/<action>", methods=["POST"])
@limiter.limit("6 per minute")
def api_toolkit(action):
    handlers = {
        "rtl_test_quick":   lambda: run_cmd(["rtl_test", "-t"], 20),
        "rtl_eeprom":       lambda: run_cmd(["rtl_eeprom"], 15),
        "lsusb_verbose":    lambda: run_cmd(["lsusb", "-v"], 10),
        "lsusb_tree":       lambda: run_cmd(["lsusb", "-t"], 10),
        "vcgencmd_temp":    lambda: run_cmd(["vcgencmd", "measure_temp"]),
        "vcgencmd_throttle":lambda: run_cmd(["vcgencmd", "get_throttled"]),
        "free":             lambda: run_cmd(["free", "-h"]),
        "df":               lambda: run_cmd(["df", "-h"]),
        "uptime":           lambda: run_cmd(["uptime"]),
        "uname":            lambda: run_cmd(["uname", "-a"]),
        "ip_addr":          lambda: run_cmd(["ip", "addr"]),
        "dmesg_usb":        _toolkit_dmesg_usb,
        "check_drivers":    _toolkit_check_drivers,
        "systeminfo":       _toolkit_systeminfo,
        "rtl_gain_sweep":   _toolkit_gain_sweep,
        "usb_reset":        _toolkit_usb_reset,
        "check_blacklist":  _toolkit_check_blacklist,
        "adsb_quality":     _toolkit_adsb_quality,
        "pi_quirks":        _toolkit_pi_quirks,
        "netstat":          lambda: run_cmd(["ss", "-tlnp"]),
        "check_usb_power":  _toolkit_usb_power,
    }
    if action not in handlers:
        return jsonify({"error": "unknown action"}), 400
    try:
        rc, out = handlers[action]()
        return jsonify({"output": out, "rc": rc})
    except Exception as e:
        log.error({"action": action, "error": str(e)})
        return jsonify({"error": str(e), "output": "", "rc": -1}), 500


def _toolkit_dmesg_usb():
    rc, out = run_cmd(["dmesg", "--color=never"], 10)
    keywords = ["rtl", "usb", "1090", "dvb", "realtek", "xhci", "ehci", "ohci"]
    lines = [l for l in out.splitlines() if any(k in l.lower() for k in keywords)]
    return 0, "\n".join(lines[-200:]) or "[no matching dmesg lines]"


def _toolkit_check_drivers():
    rc, lsmod = run_cmd(["lsmod"])
    rtl_lines = [l for l in lsmod.splitlines() if any(k in l.lower() for k in ["rtl", "dvb", "usb_serial"])]
    rc2, bl = run_cmd(["cat", "/etc/modprobe.d/rtlsdr.conf"])
    rc3, bl2 = run_cmd(["cat", "/etc/modprobe.d/blacklist-rtl.conf"])
    out = (
        "=== Loaded RTL/DVB modules ===\n"
        + ("\n".join(rtl_lines) or "(none)")
        + "\n\n=== /etc/modprobe.d/rtlsdr.conf ===\n"
        + (bl if rc2 == 0 else "(not found)")
        + "\n\n=== /etc/modprobe.d/blacklist-rtl.conf ===\n"
        + (bl2 if rc3 == 0 else "(not found)")
    )
    return 0, out


def _toolkit_check_blacklist():
    rc, out = run_cmd(["cat", "/etc/modprobe.d/rtlsdr.conf"])
    rc2, out2 = run_cmd(["cat", "/etc/modprobe.d/blacklist.conf"])
    bad_mods = ["dvb_usb_rtl28xxu", "rtl2832", "rtl2830"]
    loaded = []
    for mod in bad_mods:
        rc3, _ = run_cmd(["lsmod"])
        if mod.replace("_", "") in _.lower():
            loaded.append(mod)
    result = (
        "=== rtlsdr.conf ===\n" + (out if rc == 0 else "(missing — may cause issues)")
        + "\n\n=== blacklist.conf excerpt ===\n"
        + "\n".join(l for l in out2.splitlines() if "rtl" in l.lower() or "dvb" in l.lower())
        + "\n\n=== Potentially conflicting modules loaded ===\n"
        + ("\n".join(loaded) or "(none detected — good)")
        + "\n\nFix: echo -e 'blacklist dvb_usb_rtl28xxu\\nblacklist rtl2832\\nblacklist rtl2830' | sudo tee /etc/modprobe.d/rtlsdr.conf"
    )
    return 0, result


def _toolkit_systeminfo():
    parts = []
    for label, cmd in [
        ("uname -a", ["uname", "-a"]),
        ("uptime", ["uptime"]),
        ("free -h", ["free", "-h"]),
        ("df -h", ["df", "-h"]),
        ("ip addr", ["ip", "addr"]),
        ("ss -tlnp", ["ss", "-tlnp"]),
    ]:
        _, out = run_cmd(cmd)
        parts.append(f"=== {label} ===\n{out}")
    return 0, "\n\n".join(parts)


def _toolkit_gain_sweep():
    gains = [0, 10, 20, 30, 40, 49]
    results = ["RTL-SDR Gain Sweep (rtl_test -t -g <gain>)\n" + "=" * 50]
    for g in gains:
        rc, out = run_cmd(["rtl_test", "-t", "-g", str(g)], 8)
        summary = out.split("\n")[0] if out else "(no output)"
        results.append(f"gain={g:3d}: {summary} (rc={rc})")
    return 0, "\n".join(results)


def _toolkit_usb_reset():
    rc, out = run_cmd(["lsusb"])
    rtl_line = next(
        (l for l in out.splitlines() if any(p in l.lower() for p in ["0bda:2838", "0bda:2832", "rtl"])),
        None,
    )
    if not rtl_line:
        return 1, "[RTL-SDR not found in lsusb — cannot reset]"
    m = re.search(r"Bus (\d+) Device (\d+)", rtl_line)
    if not m:
        return 1, f"[Could not parse bus/device from: {rtl_line}]"
    bus, dev = m.group(1), m.group(2)
    dev_path = f"/dev/bus/usb/{bus.zfill(3)}/{dev.zfill(3)}"
    rc2, out2 = run_cmd(["sudo", "usb_reset", dev_path], 10)
    if rc2 != 0:
        # Try usbutils reset via echo
        rc2, out2 = run_cmd(
            ["sudo", "sh", "-c", f"echo 0 > /sys/bus/usb/devices/{bus}-{dev}/authorized && sleep 1 && echo 1 > /sys/bus/usb/devices/{bus}-{dev}/authorized"],
            15,
        )
    return rc2, f"Device: {rtl_line}\nPath: {dev_path}\n{out2}"


def _toolkit_adsb_quality():
    stats = get_dump1090_stats()
    temp = get_cpu_temp()
    throttle = get_throttle_status()
    rtl = get_rtlsdr_status()
    gain = get_piaware_gain()
    parts = [
        "=== ADS-B Signal Quality Report ===",
        f"RTL-SDR: {rtl['device']}",
        f"Gain: {gain}",
        f"Messages (last 1min): {stats.get('messages', 'N/A')}",
        f"Aircraft (last 1min): {stats.get('aircraft', 'N/A')}",
        f"Strong signals: {stats.get('strong_signals', 'N/A')}",
        f"Signal level: {stats.get('signal_dbfs', 'N/A')} dBFS",
        f"Noise floor: {stats.get('noise_dbfs', 'N/A')} dBFS",
        f"Peak signal: {stats.get('peak_signal_dbfs', 'N/A')} dBFS",
        f"CPU temp: {temp.get('celsius', '?')}°C / {temp.get('fahrenheit', '?')}°F",
        f"Throttle flags: {', '.join(throttle.get('flags', [])) or 'none'}",
        "",
        "Guidance:",
        "  Strong signals > 5%  → reduce gain",
        "  Messages < 50/min    → check antenna, gain, location",
        "  Noise > -20 dBFS     → USB3 interference likely (move to USB2 port)",
        "  Temp > 75°C          → add cooling",
    ]
    return 0, "\n".join(parts)


def _toolkit_pi_quirks():
    rc, cpuinfo = run_cmd(["cat", "/proc/cpuinfo"])
    hw_line = next((l for l in cpuinfo.splitlines() if "hardware" in l.lower()), "")
    rev_line = next((l for l in cpuinfo.splitlines() if "revision" in l.lower()), "")
    rc2, usbtree = run_cmd(["lsusb", "-t"])
    rc3, usbdev = run_cmd(["lsusb"])
    usb3 = [l for l in usbtree.splitlines() if "5000M" in l or "xhci" in l.lower()]
    quirks = [
        "=== Pi Platform Quirks Check ===",
        f"Hardware: {hw_line}",
        f"Revision: {rev_line}",
        "",
        "=== USB topology ===",
        usbtree,
        "",
        "=== USB3 ports detected ===",
        "\n".join(usb3) or "(none — USB2 only, good for RTL-SDR)",
        "",
        "Known quirks:",
        "  Pi 4/5: USB3 noise at 400MHz harmonics → use USB2 (blue) port or add USB2 hub",
        "  CM4: USB3 via PCIe bridge — same interference risk",
        "  All Pi: USB power budget 1.2A shared — use powered hub if current drops",
        "  Pi 5: New USB controller — may need kernel ≥ 6.1 for stable RTL-SDR",
        "  All Pi: Cheap USB cables cause voltage sag → use 24AWG+ cable",
    ]
    return 0, "\n".join(quirks)


def _toolkit_usb_power():
    rc, out = run_cmd(["dmesg", "--color=never"])
    power_lines = [l for l in out.splitlines() if any(
        k in l.lower() for k in ["power", "over-current", "suspend", "reset", "disconnect", "hub"]
    )]
    rc2, usbtree = run_cmd(["lsusb", "-t"])
    result = (
        "=== dmesg USB power/reset events ===\n"
        + "\n".join(power_lines[-50:])
        + "\n\n=== USB tree ===\n"
        + usbtree
        + "\n\nLook for: 'over-current', 'reset', 'disconnect' near RTL-SDR device\n"
        + "Fix options:\n"
        + "  1. Powered USB hub\n"
        + "  2. Shorter/better USB cable (24AWG)\n"
        + "  3. max_usb_current=1 in /boot/config.txt (Pi 3 only)\n"
        + "  4. Move to USB2 port if USB3 interference suspected"
    )
    return 0, result


# ─── WebSocket Terminal ─────────────────────────────────────────────────────────

class PtySession:
    def __init__(self, sid: str):
        self.sid = sid
        self.pid: int | None = None
        self.fd: int | None = None
        self.alive = False
        self._lock = threading.Lock()

    def start(self, cols: int = 220, rows: int = 50) -> int:
        """Fork a PTY and exec bash. Returns master fd."""
        master_fd, slave_fd = pty.openpty()
        child_pid = os.fork()
        if child_pid == 0:
            # ── child ──
            os.close(master_fd)
            os.setsid()
            # Make slave the controlling terminal
            fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)
            # Wire stdio
            for fd in range(3):
                os.dup2(slave_fd, fd)
            if slave_fd > 2:
                os.close(slave_fd)
            # Terminal size
            try:
                winsize = struct.pack("HHHH", rows, cols, 0, 0)
                fcntl.ioctl(0, termios.TIOCSWINSZ, winsize)
            except Exception:
                pass
            env = {
                "TERM": "xterm-256color",
                "HOME": os.environ.get("HOME", "/home/pi"),
                "USER": os.environ.get("USER", "pi"),
                "LOGNAME": os.environ.get("USER", "pi"),
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "PS1": r"\[\033[01;32m\][rtl-debug]\[\033[00m\] \[\033[01;34m\]\w\[\033[00m\] \$ ",
                "SHELL": "/bin/bash",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "COLORTERM": "truecolor",
            }
            os.execve("/bin/bash", ["/bin/bash", "--norc", "--noprofile"], env)
            os._exit(1)
        else:
            # ── parent ──
            os.close(slave_fd)
            self.pid = child_pid
            self.fd = master_fd
            self.alive = True
            # Non-blocking reads
            flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
            fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
            # Set terminal size on master
            try:
                winsize = struct.pack("HHHH", rows, cols, 0, 0)
                fcntl.ioctl(master_fd, termios.TIOCSWINSZ, winsize)
            except Exception:
                pass
            return master_fd

    def resize(self, cols: int, rows: int):
        if self.fd:
            try:
                winsize = struct.pack("HHHH", rows, cols, 0, 0)
                fcntl.ioctl(self.fd, termios.TIOCSWINSZ, winsize)
            except Exception:
                pass

    def write(self, data):
        if self.fd and self.alive:
            try:
                raw = data.encode() if isinstance(data, str) else data
                os.write(self.fd, raw)
            except OSError:
                self.alive = False

    def stop(self):
        self.alive = False
        if self.pid:
            try:
                os.kill(self.pid, signal.SIGTERM)
            except Exception:
                pass
            try:
                os.waitpid(self.pid, os.WNOHANG)
            except Exception:
                pass
        if self.fd:
            try:
                os.close(self.fd)
            except Exception:
                pass
        self.pid = None
        self.fd = None


_sessions: dict[str, PtySession] = {}
_sessions_lock = threading.Lock()

# Per-sid input rate limiting  (bytes/sec)
_rate: dict[str, list] = {}   # sid -> [bytes_this_window, window_start]
_RATE_LIMIT_BYTES = 65536      # 64 KB per second max input


def _pty_reader(session: PtySession):
    """Greenlet: relay PTY output → SocketIO."""
    fd = session.fd
    sid = session.sid
    while session.alive:
        try:
            r, _, _ = select.select([fd], [], [], 0.05)
            if r:
                chunk = os.read(fd, 4096)
                if not chunk:
                    break
                socketio.emit(
                    "output",
                    {"data": chunk.decode("utf-8", errors="replace")},
                    to=sid,
                    namespace="/terminal",
                )
            else:
                eventlet.sleep(0)
        except BlockingIOError:
            eventlet.sleep(0.01)
        except OSError:
            break
        except Exception as e:
            log.error({"reader_error": str(e), "sid": sid})
            break
    session.alive = False
    socketio.emit("pty_closed", {}, to=sid, namespace="/terminal")


@socketio.on("connect", namespace="/terminal")
def on_terminal_connect():
    sid = request.sid
    log.info({"event": "terminal_connect", "sid": sid, "ip": request.remote_addr})
    session = PtySession(sid)
    fd = session.start()
    with _sessions_lock:
        _sessions[sid] = session
        _rate[sid] = [0, time.time()]
    # Spawn reader greenlet
    eventlet.spawn(_pty_reader, session)
    emit("connected", {"sid": sid})
    # Send welcome banner
    banner = (
        "\033[32m╔══════════════════════════════════════════╗\r\n"
        "║   PiAware RTL-SDR Expert Console         ║\r\n"
        "║   Type commands or use Toolkit buttons   ║\r\n"
        "╚══════════════════════════════════════════╝\033[0m\r\n\r\n"
    )
    session.write(f"echo -e '{banner}'; ")


@socketio.on("disconnect", namespace="/terminal")
def on_terminal_disconnect():
    sid = request.sid
    log.info({"event": "terminal_disconnect", "sid": sid})
    with _sessions_lock:
        if sid in _sessions:
            _sessions[sid].stop()
            del _sessions[sid]
        _rate.pop(sid, None)


@socketio.on("input", namespace="/terminal")
def on_terminal_input(data):
    sid = request.sid
    raw = data.get("data", "")
    if not raw:
        return
    # Rate limit
    now = time.time()
    with _sessions_lock:
        if sid not in _rate:
            _rate[sid] = [0, now]
        r = _rate[sid]
        if now - r[1] >= 1.0:
            r[0] = 0
            r[1] = now
        r[0] += len(raw)
        if r[0] > _RATE_LIMIT_BYTES:
            emit("output", {"data": "\r\n\033[31m[INPUT RATE LIMIT — slow down]\033[0m\r\n"})
            return
        session = _sessions.get(sid)
    if session:
        session.write(raw)


@socketio.on("resize", namespace="/terminal")
def on_terminal_resize(data):
    sid = request.sid
    cols = max(10, min(int(data.get("cols", 220)), 500))
    rows = max(5, min(int(data.get("rows", 50)), 200))
    with _sessions_lock:
        session = _sessions.get(sid)
    if session:
        session.resize(cols, rows)


@socketio.on("run_toolkit_cmd", namespace="/terminal")
def on_run_toolkit_cmd(data):
    """Send a whitelisted command string to the PTY as if typed."""
    sid = request.sid
    cmd = data.get("cmd", "").strip()
    if not cmd:
        return
    if not is_safe_command(cmd):
        emit("output", {
            "data": f"\r\n\033[31m[BLOCKED] Not in whitelist: {cmd}\033[0m\r\n"
        })
        return
    with _sessions_lock:
        session = _sessions.get(sid)
    if session:
        session.write(cmd + "\n")


# ─── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    log.info({"msg": f"Starting PiAware RTL-SDR Troubleshooter", "port": PORT})
    socketio.run(app, host="0.0.0.0", port=PORT, debug=False, use_reloader=False)
