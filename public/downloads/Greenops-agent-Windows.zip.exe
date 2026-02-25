#!/usr/bin/env python3
"""
GreenOps Agent v2.0.0
Cross-platform agent for Windows and Linux/macOS.
"""
import ctypes
import hashlib
import json
import logging
import os
import platform
import re
import signal
import socket
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Any
from urllib.error import HTTPError, URLError
from urllib.request import Request as UrlRequest, urlopen

DEFAULTS = {
    "server_url": "http://localhost:8000",
    "heartbeat_interval": 60,
    "idle_threshold": 300,
    "log_level": "INFO",
    "retry_max_attempts": 5,
    "retry_base_delay": 10,
    "offline_queue_max": 100,
    "agent_version": "2.0.0",
}


def _get_log_dir() -> Path:
    if platform.system() == "Windows":
        return Path(os.environ.get("PROGRAMDATA", "C:\\ProgramData")) / "GreenOps"
    return Path.home() / ".greenops"


def setup_logging(log_dir: Path, log_level: str = "INFO") -> logging.Logger:
    log_dir.mkdir(parents=True, exist_ok=True)
    level = getattr(logging, log_level.upper(), logging.INFO)
    formatter = logging.Formatter("%(asctime)s %(levelname)-8s %(message)s", datefmt="%Y-%m-%dT%H:%M:%S")
    handlers = [logging.StreamHandler(sys.stdout)]
    try:
        from logging.handlers import RotatingFileHandler
        fh = RotatingFileHandler(log_dir / "agent.log", maxBytes=10*1024*1024, backupCount=5, encoding="utf-8")
        fh.setFormatter(formatter)
        handlers.append(fh)
    except (PermissionError, OSError):
        pass
    for h in handlers:
        h.setFormatter(formatter)
    logger = logging.getLogger("greenops.agent")
    logger.setLevel(level)
    for h in handlers:
        logger.addHandler(h)
    logger.propagate = False
    return logger


def load_config() -> Dict[str, Any]:
    config = dict(DEFAULTS)
    config_path = Path.home() / ".greenops" / "config.json"
    if platform.system() == "Windows":
        config_path = Path(os.environ.get("PROGRAMDATA", "C:\\ProgramData")) / "GreenOps" / "config.json"
    if config_path.exists():
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                config.update(json.load(f))
        except Exception:
            pass
    for env_key, config_key in {
        "GREENOPS_SERVER_URL": "server_url",
        "GREENOPS_HEARTBEAT_INTERVAL": "heartbeat_interval",
        "GREENOPS_IDLE_THRESHOLD": "idle_threshold",
        "GREENOPS_LOG_LEVEL": "log_level",
        "GREENOPS_AGENT_TOKEN": "agent_token",
        "GREENOPS_MACHINE_ID": "machine_id",
    }.items():
        val = os.environ.get(env_key)
        if val:
            if config_key in ("heartbeat_interval", "idle_threshold"):
                try:
                    val = int(val)
                except ValueError:
                    pass
            config[config_key] = val
    config["server_url"] = config["server_url"].rstrip("/")
    return config


def save_config(config: Dict[str, Any], config_path: Path):
    persist_keys = {"server_url", "heartbeat_interval", "idle_threshold", "log_level", "agent_token", "machine_id"}
    config_path.parent.mkdir(parents=True, exist_ok=True)
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump({k: v for k, v in config.items() if k in persist_keys}, f, indent=2)


def get_mac_address() -> str:
    system = platform.system()
    if system == "Linux":
        try:
            net_dir = Path("/sys/class/net")
            for iface in sorted(net_dir.iterdir()):
                if iface.name.startswith(("eth", "ens", "enp", "em", "eno")):
                    addr_file = iface / "address"
                    if addr_file.exists():
                        mac = addr_file.read_text().strip().upper()
                        if re.match(r"[0-9A-F]{2}(:[0-9A-F]{2}){5}", mac):
                            return mac
        except Exception:
            pass
    mac_int = uuid.getnode()
    return ":".join(f"{(mac_int >> (i * 8)) & 0xFF:02X}" for i in range(5, -1, -1))


def get_idle_seconds() -> int:
    system = platform.system()
    if system == "Windows":
        try:
            class LASTINPUTINFO(ctypes.Structure):
                _fields_ = [("cbSize", ctypes.c_uint), ("dwTime", ctypes.c_uint)]
            lii = LASTINPUTINFO()
            lii.cbSize = ctypes.sizeof(LASTINPUTINFO)
            if ctypes.windll.user32.GetLastInputInfo(ctypes.byref(lii)):
                return max(0, (ctypes.windll.kernel32.GetTickCount() - lii.dwTime) // 1000)
        except Exception:
            pass
    elif system == "Linux":
        try:
            result = subprocess.run(["xprintidle"], capture_output=True, text=True, timeout=5,
                env={**os.environ, "DISPLAY": os.environ.get("DISPLAY", ":0")})
            if result.returncode == 0:
                return int(result.stdout.strip()) // 1000
        except Exception:
            pass
        try:
            with open("/proc/uptime") as f:
                return int(float(f.read().split()[0]))
        except Exception:
            pass
    return 0


def get_cpu_percent() -> Optional[float]:
    try:
        import psutil
        return psutil.cpu_percent(interval=1)
    except ImportError:
        pass
    if platform.system() == "Linux":
        try:
            with open("/proc/stat") as f:
                line = f.readline()
            vals = [int(x) for x in line.split()[1:]]
            idle1, total1 = vals[3], sum(vals)
            time.sleep(0.1)
            with open("/proc/stat") as f:
                line = f.readline()
            vals = [int(x) for x in line.split()[1:]]
            idle2, total2 = vals[3], sum(vals)
            return round((1 - (idle2 - idle1) / (total2 - total1)) * 100, 1)
        except Exception:
            pass
    return None


def get_memory_percent() -> Optional[float]:
    try:
        import psutil
        return psutil.virtual_memory().percent
    except ImportError:
        pass
    return None


class GreenOpsAgent:
    def __init__(self):
        self.config = load_config()
        self.log_dir = _get_log_dir()
        self.logger = setup_logging(self.log_dir, self.config.get("log_level", "INFO"))
        self.config_path = Path.home() / ".greenops" / "config.json"
        if platform.system() == "Windows":
            self.config_path = Path(os.environ.get("PROGRAMDATA", "C:\\ProgramData")) / "GreenOps" / "config.json"
        self._running = False

    def _request(self, method: str, path: str, data: Optional[dict] = None, token: Optional[str] = None) -> dict:
        url = f"{self.config['server_url']}{path}"
        body = json.dumps(data).encode("utf-8") if data else None
        headers = {
            "Content-Type": "application/json",
            "User-Agent": f"GreenOps-Agent/2.0.0 ({platform.system()})",
            "Accept": "application/json",
        }
        auth_token = token or self.config.get("agent_token")
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"
        req = UrlRequest(url, data=body, headers=headers, method=method)
        resp = urlopen(req, timeout=30)
        body = resp.read().decode("utf-8")
        return json.loads(body) if body else {}

    def register(self) -> bool:
        if self.config.get("agent_token") and self.config.get("machine_id"):
            self.logger.info("Already registered, machine_id=%s", self.config["machine_id"])
            return True
        mac = get_mac_address()
        hostname = socket.gethostname()
        os_type = platform.system()
        os_version = platform.version()
        payload = {"mac_address": mac, "hostname": hostname, "os_type": os_type,
                   "os_version": os_version, "agent_version": "2.0.0"}
        self.logger.info("Registering: hostname=%s mac=%s", hostname, mac)
        for attempt in range(1, 6):
            try:
                resp = self._request("POST", "/api/agents/register", payload)
                token = resp.get("token")
                machine_id = resp.get("machine_id")
                if not token or not machine_id:
                    raise ValueError("Invalid registration response")
                self.config["agent_token"] = token
                self.config["machine_id"] = machine_id
                save_config(self.config, self.config_path)
                self.logger.info("Registered successfully, machine_id=%s", machine_id)
                return True
            except HTTPError as e:
                self.logger.error("Registration failed HTTP %d", e.code)
                if e.code in (400, 422):
                    return False
            except (URLError, OSError) as e:
                self.logger.warning("Registration attempt %d failed: %s", attempt, e)
            except Exception as e:
                self.logger.error("Unexpected registration error: %s", e)
            if attempt < 5:
                time.sleep(min(10 * (2 ** (attempt - 1)), 300))
        return False

    def send_heartbeat(self, idle_seconds: int, cpu: Optional[float], memory: Optional[float]) -> bool:
        payload = {"idle_seconds": idle_seconds, "cpu_usage": cpu, "memory_usage": memory,
                   "timestamp": datetime.now(timezone.utc).isoformat(), "ip_address": None}
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            payload["ip_address"] = s.getsockname()[0]
            s.close()
        except Exception:
            pass
        try:
            resp = self._request("POST", "/api/agents/heartbeat", payload)
            self.logger.info("Heartbeat OK | status=%s idle=%ds", resp.get("machine_status", ""), idle_seconds)
            return True
        except HTTPError as e:
            if e.code == 401:
                self.config.pop("agent_token", None)
                self.config.pop("machine_id", None)
                save_config(self.config, self.config_path)
            self.logger.warning("Heartbeat HTTP error %d", e.code)
        except Exception as e:
            self.logger.warning("Heartbeat failed: %s", e)
        return False

    def run(self):
        self.logger.info("GreenOps Agent v2.0.0 starting on %s", platform.system())
        if not self.register():
            self.logger.error("Could not register. Exiting.")
            sys.exit(1)
        self._running = True
        interval = self.config.get("heartbeat_interval", 60)

        def _shutdown(sig, frame):
            self._running = False

        signal.signal(signal.SIGTERM, _shutdown)
        signal.signal(signal.SIGINT, _shutdown)

        while self._running:
            try:
                if not self.config.get("agent_token"):
                    self.logger.info("Re-registering...")
                    if not self.register():
                        time.sleep(60)
                        continue
                idle = get_idle_seconds()
                cpu = get_cpu_percent()
                mem = get_memory_percent()
                self.send_heartbeat(idle, cpu, mem)
            except Exception as e:
                self.logger.error("Main loop error: %s", e, exc_info=True)
            elapsed = 0
            while elapsed < interval and self._running:
                time.sleep(min(5, interval - elapsed))
                elapsed += 5
        self.logger.info("GreenOps Agent stopped.")


if __name__ == "__main__":
    GreenOpsAgent().run()
