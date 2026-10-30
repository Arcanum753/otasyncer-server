#!/usr/bin/env python3
"""
OTA Firmware Server + UDP Device Monitor
=========================================
Сервер раздачи прошивок (OTA) и сбора статистики UDP-устройств.

Основан на логике C#-примеров:
  - example/AppSettings.cs  — настройки UDP и светофора
  - example/jsonclasses.cs  — модель fota_dev_info
  - example/udp.cs          — UDP приём/передача (super-broadcast)
"""

import os
import sys
import json
import hashlib
import logging
import threading
import socket
import struct
import time
import queue
import copy
import re
import shutil
import ipaddress
import fnmatch
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional
from urllib.parse import quote

import requests

from flask import Flask, request, redirect, url_for, send_file, jsonify, render_template, Response
from werkzeug.utils import secure_filename

# ============================================================
# Константы
# ============================================================
CONFIG_FILE = os.environ.get('OTASYNCER_CONFIG', 'config.json')
DEVICES_DB_FILE = os.environ.get('OTASYNCER_DEVICES_DB', 'devices_db.json')
DISPLAY_FORMAT_FILE = 'display_format.json'
TEST_MODE = os.environ.get('OTASYNCER_TEST') == '1'

# Максимальное количество записей в логе событий
MAX_EVENT_LOG_SIZE = 200

DEFAULT_CONFIG = {
    "host": "0.0.0.0",
    "port": 8080,
    "firmware_dirs": [{"path": "./firmware", "delete_old_versions": False}],
    "manifest_path": "/manifest.json",
    "manifest": {},
    "device_username": "",
    "device_password": "",
    "device_http_port": 80,
    "backup": {
        "dir": "./backups",
        "timeout_s": 10,
        "upload_timeout_s": 30,
        "inter_request_delay_ms": 150,
        "max_file_bytes": 1048576,
        "keep_manual": 10,
        "restore_verify": "size",
        "include_patterns": ["/config_*.json", "/secret.json", "/macros/*.lua", "/avrisp.json"],
        "exclude_patterns": ["/_version_fs.json", "/*_cfg.json"],
        "extra_config_files": []
    },
    "fs_update": {
        "keep_snapshots": 5,
        "reconnect_timeout_s": 300,
        "status_poll_s": 3,
        "restart_after_restore": True
    },
    "udp_listener": {
        "is_listening": True,
        "receive_port": 40000,
        "transmit_port": 40001,
        "keyword": "Ave_Omnissiah",
        "device_timeout_minutes": 10,
        "device_cleanup_hours": 24,
        "probe_devices_on_startup": True
    },
    "traffic_light": {
        "is_minutes_mode": True,
        "green_time": 1,
        "yellow_time": 2,
        "red_time": 3
    },
    "logging": {
        "enabled": True,
        "directory": "log"
    }
}

DEFAULT_DISPLAY_FORMAT = {
    "columns": [
        {"field": "status",      "label": "Status",      "width": 60,   "visible": True},
        {"field": "deviceName",  "label": "Device Name",  "width": 150,  "visible": True},
        {"field": "ip",          "label": "IP Address",   "width": 130,  "visible": True},
        {"field": "mac",         "label": "MAC Address",  "width": 150,  "visible": True},
        {"field": "target",      "label": "Platform",     "width": 100,  "visible": True},
        {"field": "espVer",      "label": "FW Version",   "width": 80,   "visible": True},
        {"field": "uptime",      "label": "Uptime",       "width": 120,  "visible": True},
        {"field": "rstreason",   "label": "Reset Reason", "width": 130,  "visible": True},
        {"field": "lastSeen",    "label": "Last Seen",    "width": 160,  "visible": True},
        {"field": "deviceSerial","label": "Serial",       "width": 100,  "visible": False},
        {"field": "buildtime",   "label": "Build Time",   "width": 140,  "visible": False},
        {"field": "gitbranch",   "label": "Git Branch",   "width": 100,  "visible": False},
        {"field": "gitcommit",   "label": "Git Commit",   "width": 100,  "visible": False},
        {"field": "webVer",      "label": "Web Version",  "width": 80,   "visible": False},
        {"field": "udpPortTx",   "label": "UDP TX Port",  "width": 80,   "visible": False},
        {"field": "udpPortRx",   "label": "UDP RX Port",  "width": 80,   "visible": False},
        {"field": "udpTimeOut",  "label": "UDP Timeout",  "width": 80,   "visible": False},
        {"field": "keyword",     "label": "Keyword",      "width": 120,  "visible": False}
    ]
}

# ============================================================
# Бэкап конфигов и скриптов с устройств
# ============================================================
BACKUP_SCHEMA_VERSION = 2
BACKUP_DEFAULT_DIR = "./backups"
BACKUP_DEFAULT_TIMEOUT_S = 10
BACKUP_DEFAULT_UPLOAD_TIMEOUT_S = 30
BACKUP_DEFAULT_DELAY_MS = 150
BACKUP_DEFAULT_MAX_FILE_BYTES = 1024 * 1024
BACKUP_DEFAULT_KEEP_MANUAL = 10
BACKUP_DEFAULT_INCLUDE = ["/config_*.json", "/secret.json", "/macros/*.lua", "/avrisp.json"]
BACKUP_DEFAULT_EXCLUDE = ["/_version_fs.json", "/*_cfg.json"]
CORE_FS_API_VERSION = 1

_WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *{f"COM{i}" for i in range(1, 10)},
    *{f"LPT{i}" for i in range(1, 10)},
}

# ============================================================
# Flask приложение
# ============================================================
app = Flask(__name__)

# ============================================================
# Фильтр логов Werkzeug — убираем TLS-мусор из консоли
# ============================================================
class _WerkzeugLogFilter(logging.Filter):
    def filter(self, record):
        msg = record.getMessage()
        if "Bad request version" in msg or "Bad HTTP/0.9" in msg:
            return False
        return True

logging.getLogger("werkzeug").addFilter(_WerkzeugLogFilter())


# ============================================================
# Файловые логи с почасовой ротацией
# ============================================================
class HourlyFileTee:
    """
    Перенаправляет stdout/stderr (в т.ч. print и логи werkzeug) в консоль
    и одновременно в файл с почасовой ротацией.
    Имя файла: <prefix>_YYYYMMDD_HHMMSS.log (маска по началу текущего часа).
    """

    def __init__(self, directory: str = "log", prefix: str = "otasyncer", enabled: bool = True):
        self._lock = threading.Lock()
        self._directory = directory
        self._prefix = prefix
        self._enabled = bool(enabled)
        self._fh = None
        self._period_key = None
        self._console = sys.__stdout__

    def set_enabled(self, enabled: bool):
        with self._lock:
            self._enabled = bool(enabled)
            if not self._enabled:
                self._close_locked()

    def set_directory(self, directory: str):
        with self._lock:
            if directory != self._directory:
                self._directory = directory
                self._close_locked()
                self._period_key = None

    @property
    def enabled(self) -> bool:
        return self._enabled

    def _close_locked(self):
        if self._fh is not None:
            try:
                self._fh.flush()
                self._fh.close()
            except Exception:
                pass
            self._fh = None

    def _ensure_open_locked(self):
        if not self._enabled:
            return
        now = datetime.now().replace(minute=0, second=0, microsecond=0)
        key = now.strftime("%Y%m%d_%H%M%S")
        if self._fh is not None and key == self._period_key:
            return
        self._close_locked()
        try:
            os.makedirs(self._directory, exist_ok=True)
            path = os.path.join(self._directory, f"{self._prefix}_{key}.log")
            self._fh = open(path, "a", encoding="utf-8")
            self._period_key = key
        except Exception as e:
            self._fh = None
            self._period_key = None
            try:
                self._console.write(f"[log] open file error: {e}\n")
            except Exception:
                pass

    def write(self, data):
        if not data:
            return
        with self._lock:
            if self._enabled:
                try:
                    self._ensure_open_locked()
                    if self._fh is not None:
                        self._fh.write(data)
                        if not data.endswith("\n"):
                            self._fh.write("\n")
                        self._fh.flush()
                except Exception:
                    pass
        try:
            self._console.write(data)
            self._console.flush()
        except Exception:
            pass

    def flush(self):
        with self._lock:
            if self._fh is not None:
                try:
                    self._fh.flush()
                except Exception:
                    pass
        try:
            self._console.flush()
        except Exception:
            pass

    def isatty(self):
        return False


log_tee = HourlyFileTee(enabled=False)


def apply_logging_config(logging_cfg: dict):
    """Применить настройки логирования (папка + вкл/выкл) к log_tee."""
    global log_tee
    directory = str(logging_cfg.get("directory", "log") or "log")
    log_tee.set_directory(directory)
    log_tee.set_enabled(bool(logging_cfg.get("enabled", True)))


# Всегда перенаправляем вывод в tee: если файловые логи выключены,
# tee работает как прозрачный проброс в консоль.
sys.stdout = log_tee
sys.stderr = log_tee


# ============================================================
# Кастомный обработчик ошибок — понятное сообщение вместо 400
# ============================================================
@app.errorhandler(400)
def _bad_request(error):
    ip = request.remote_addr or 'unknown'
    msg = str(error)
    if "Bad request version" in msg or "Bad HTTP/0.9" in msg:
        print(f"[WARN] TLS/HTTPS request from {ip} — браузер пытается открыть HTTPS вместо HTTP")
        return "<html><body><h2>HTTPS не поддерживается</h2><p>Используйте <b>http://</b>, а не https://</p></body></html>", 400
    return error, 400


# ============================================================
# Модель данных устройства (аналог fota_dev_info из jsonclasses.cs)
# ============================================================
@dataclass
class DeviceInfo:
    """Модель устройства, получаемая из UDP broadcast."""
    mac: str = ""
    deviceName: str = ""
    deviceSerial: str = ""
    ip: str = ""
    target: str = ""
    uptime: str = ""
    rstreason: str = ""
    espVer: str = ""
    webVer: str = ""
    buildtime: str = ""
    gitbranch: str = ""
    gitcommit: str = ""
    udpPortTx: int = 0
    udpPortRx: int = 0
    udpTimeOut: int = 0
    keyword: str = ""
    # Служебные поля
    lastSeen: str = ""
    firstSeen: str = ""
    isOnline: bool = True
    # Разрешения на автообновление (сервер решает через манифест)
    # По умолчанию запрещены — новые устройства не обновляются автоматически,
    # пока администратор явно не разрешит в /devices.
    allowFsUpdate: bool = False
    allowFwUpdate: bool = False

    @staticmethod
    def from_json(data: dict) -> 'DeviceInfo':
        """Создать DeviceInfo из JSON, полученного от устройства."""
        now_iso = datetime.now(timezone.utc).isoformat()
        return DeviceInfo(
            mac=data.get("mac", ""),
            deviceName=data.get("deviceName", ""),
            deviceSerial=data.get("deviceSerial", ""),
            ip=data.get("ip", ""),
            target=data.get("target", ""),
            uptime=data.get("uptime", ""),
            rstreason=data.get("rstreason", ""),
            espVer=data.get("espVer", ""),
            webVer=data.get("webVer", ""),
            buildtime=data.get("buildtime", ""),
            gitbranch=data.get("gitbranch", ""),
            gitcommit=data.get("gitcommit", ""),
            udpPortTx=int(data.get("udpPortTx", 0)),
            udpPortRx=int(data.get("udpPortRx", 0)),
            udpTimeOut=int(data.get("udpTimeOut", 0)),
            keyword=data.get("keyword", ""),
            lastSeen=now_iso,
            firstSeen=now_iso,
            isOnline=True
        )

    def to_dict(self) -> dict:
        """Сериализация в dict для JSON."""
        return asdict(self)


# ============================================================
# Лог событий (in-memory)
# ============================================================
class EventLog:
    """Потокобезопасный буфер последних событий в памяти."""

    def __init__(self, max_size: int = MAX_EVENT_LOG_SIZE):
        self._lock = threading.Lock()
        self._events: list[dict] = []
        self._max_size = max_size

    def add(self, event: dict):
        """Добавить событие в лог."""
        with self._lock:
            self._events.insert(0, event)
            if len(self._events) > self._max_size:
                self._events.pop()

    def get_all(self) -> list[dict]:
        """Получить копию всех событий."""
        with self._lock:
            return list(self._events)

    def clear(self):
        """Очистить лог."""
        with self._lock:
            self._events.clear()


# ============================================================
# SSE Manager (Server-Sent Events)
# ============================================================
class SseManager:
    """Управление подписчиками SSE и рассылка событий."""

    def __init__(self):
        self._lock = threading.Lock()
        self._subscribers: list[queue.Queue] = []

    def subscribe(self) -> queue.Queue:
        """Создать новую очередь для подписчика."""
        q = queue.Queue(maxsize=100)
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue):
        """Удалить подписчика."""
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def broadcast(self, event_data: dict):
        """Отправить событие всем подписчикам."""
        with self._lock:
            dead = []
            for q in self._subscribers:
                try:
                    q.put_nowait(event_data)
                except queue.Full:
                    dead.append(q)
            for q in dead:
                self._subscribers.remove(q)

    @property
    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subscribers)


# ============================================================
# Хранилище устройств (devices_db.json)
# ============================================================
class DeviceStorage:
    """Хранилище устройств в JSON-файле."""

    def __init__(self, filepath: str):
        self._filepath = filepath
        self._lock = threading.Lock()
        self._devices: dict[str, DeviceInfo] = {}  # key = mac
        self._load()

    # ---- Внутренние методы ----

    def _load(self):
        """Загрузить устройства из файла."""
        if not os.path.exists(self._filepath):
            self._devices = {}
            return
        try:
            with open(self._filepath, 'r') as f:
                data = json.load(f)
            devices_list = data.get("devices", [])
            for d in devices_list:
                mac = d.get("mac", "")
                if mac:
                    dev = DeviceInfo(**d)
                    self._devices[mac] = dev
        except Exception as e:
            print(f"Error loading devices DB: {e}")
            self._devices = {}

    def _save(self):
        """Сохранить устройства в файл."""
        try:
            devices_list = [dev.to_dict() for dev in self._devices.values()]
            with open(self._filepath, 'w') as f:
                json.dump({"devices": devices_list}, f, indent=4)
        except Exception as e:
            print(f"Error saving devices DB: {e}")

    # ---- Публичные методы ----

    def update_device(self, data: dict) -> tuple[DeviceInfo, bool]:
        """
        Обновить или создать устройство.
        Вызывается при получении UDP-пакета от устройства.
        Возвращает (DeviceInfo, is_new).
        """
        with self._lock:
            mac = data.get("mac", "")
            if not mac:
                return None, False

            now_iso = datetime.now(timezone.utc).isoformat()
            is_new = False

            if mac in self._devices:
                # Обновляем существующее
                dev = self._devices[mac]
                dev.deviceName = data.get("deviceName", dev.deviceName)
                dev.deviceSerial = data.get("deviceSerial", dev.deviceSerial)
                dev.ip = data.get("ip", dev.ip)
                dev.target = data.get("target", dev.target)
                dev.uptime = data.get("uptime", dev.uptime)
                dev.rstreason = data.get("rstreason", dev.rstreason)
                dev.espVer = data.get("espVer", dev.espVer)
                dev.webVer = data.get("webVer", dev.webVer)
                dev.buildtime = data.get("buildtime", dev.buildtime)
                dev.gitbranch = data.get("gitbranch", dev.gitbranch)
                dev.gitcommit = data.get("gitcommit", dev.gitcommit)
                dev.udpPortTx = int(data.get("udpPortTx", dev.udpPortTx))
                dev.udpPortRx = int(data.get("udpPortRx", dev.udpPortRx))
                dev.udpTimeOut = int(data.get("udpTimeOut", dev.udpTimeOut))
                dev.keyword = data.get("keyword", dev.keyword)
                dev.lastSeen = now_iso
                dev.isOnline = True
            else:
                # Создаём новое
                dev = DeviceInfo.from_json(data)
                self._devices[mac] = dev
                is_new = True

            self._save()
            return dev, is_new

    def clear_all(self):
        """Очистить все устройства."""
        with self._lock:
            self._devices.clear()
            self._save()

    def get_all_devices(self) -> list[DeviceInfo]:
        """Получить список всех устройств."""
        with self._lock:
            return list(self._devices.values())

    def get_device_by_mac(self, mac: str) -> Optional[DeviceInfo]:
        """Получить устройство по MAC."""
        with self._lock:
            return self._devices.get(mac)

    def set_update_policy(self, mac: str, fw: Optional[bool] = None, fs: Optional[bool] = None) -> Optional[DeviceInfo]:
        """
        Обновить разрешения на автообновление устройства.
        Переданные аргументы None не меняются. Возвращает обновлённое устройство
        или None, если устройство не найдено.
        """
        with self._lock:
            dev = self._devices.get(mac)
            if dev is None:
                return None
            if fw is not None:
                dev.allowFwUpdate = bool(fw)
            if fs is not None:
                dev.allowFsUpdate = bool(fs)
            self._save()
            return dev

    def find_device_for_update(self, ip: str, target: str = "") -> Optional[DeviceInfo]:
        """
        Найти устройство для запроса манифеста по IP источника HTTP-запроса.
        Среди устройств с совпавшим ip предпочитаем совпадение target,
        затем онлайн-устройство, затем самое свежее lastSeen.
        """
        if not ip:
            return None
        candidates = []
        with self._lock:
            for dev in self._devices.values():
                if dev.ip != ip:
                    continue
                key = 0
                if target and dev.target == target:
                    key += 4
                if dev.isOnline:
                    key += 2
                candidates.append((key, dev))
        if not candidates:
            return None
        # sort: key убывает, среди равных — свежее lastSeen первым
        candidates.sort(key=lambda x: (x[0], x[1].lastSeen), reverse=True)
        return candidates[0][1]

    def get_devices_since(self, minutes: int = 0) -> list[DeviceInfo]:
        """
        Получить устройства, замеченные за последние N минут.
        Если minutes == 0 — вернуть все.
        """
        if minutes <= 0:
            return self.get_all_devices()

        cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
        result = []
        with self._lock:
            for dev in self._devices.values():
                try:
                    last = datetime.fromisoformat(dev.lastSeen)
                    if last >= cutoff:
                        result.append(dev)
                except:
                    result.append(dev)
        return result

    def mark_offline(self):
        """Пометить устройства как офлайн, если от них давно не было пакетов."""
        timeout_min = config.get("udp_listener", {}).get("device_timeout_minutes", 10)
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=timeout_min)
        changed = False
        with self._lock:
            for dev in self._devices.values():
                if dev.isOnline:
                    try:
                        last = datetime.fromisoformat(dev.lastSeen)
                        if last < cutoff:
                            dev.isOnline = False
                            changed = True
                    except:
                        pass
            if changed:
                self._save()

    def cleanup_old(self):
        """Удалить устройства, которые не появлялись дольше device_cleanup_hours."""
        cleanup_hours = config.get("udp_listener", {}).get("device_cleanup_hours", 24)
        cutoff = datetime.now(timezone.utc) - timedelta(hours=cleanup_hours)
        to_remove = []
        with self._lock:
            for mac, dev in self._devices.items():
                try:
                    last = datetime.fromisoformat(dev.lastSeen)
                    # Удаляем только записи с политикой по умолчанию (оба запрещены).
                    # Устройства, которым администратор явно разрешил обновления,
                    # сохраняем: иначе при возврате устройства явное разрешение
                    # потеряется (запись создастся заново с запретом по умолчанию).
                    if last < cutoff and not dev.allowFwUpdate and not dev.allowFsUpdate:
                        to_remove.append(mac)
                except:
                    pass
            for mac in to_remove:
                del self._devices[mac]
            if to_remove:
                self._save()

    def get_online_count(self) -> int:
        """Количество онлайн-устройств."""
        with self._lock:
            return sum(1 for d in self._devices.values() if d.isOnline)

    def get_total_count(self) -> int:
        """Общее количество устройств."""
        with self._lock:
            return len(self._devices)


# ============================================================
# Вспомогательные функции для конфигурации
# ============================================================
def normalize_firmware_dirs(dirs):
    """
    Normalize firmware_dirs config to list of dicts.
    Supports backward compatibility with old format (list of strings).
    """
    normalized = []
    for entry in dirs:
        if isinstance(entry, str):
            normalized.append({"path": entry, "delete_old_versions": False})
        elif isinstance(entry, dict):
            normalized.append({
                "path": entry.get("path", "./firmware"),
                "delete_old_versions": entry.get("delete_old_versions", False)
            })
        else:
            normalized.append({"path": "./firmware", "delete_old_versions": False})
    return normalized


# ============================================================
# Загрузка/сохранение конфигурации
# ============================================================
def load_config():
    """Загрузить конфигурацию из файла."""
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                cfg = json.load(f)
            merged = copy.deepcopy(DEFAULT_CONFIG)
            merged.update(cfg)
            # Убедимся, что вложенные секции есть
            for section in ['udp_listener', 'traffic_light', 'manifest', 'logging', 'backup', 'fs_update']:
                if section not in merged or not isinstance(merged[section], dict):
                    merged[section] = copy.deepcopy(DEFAULT_CONFIG[section])
                else:
                    dflt = DEFAULT_CONFIG[section]
                    for k, v in dflt.items():
                        if k not in merged[section]:
                            merged[section][k] = copy.deepcopy(v)
            # Ensure firmware_dirs is a list and normalize to dict format
            if not isinstance(merged["firmware_dirs"], list):
                merged["firmware_dirs"] = [merged["firmware_dirs"]]
            merged["firmware_dirs"] = normalize_firmware_dirs(merged["firmware_dirs"])
            return merged
        except Exception as e:
            print(f"Error loading config: {e}")
            return copy.deepcopy(DEFAULT_CONFIG)
    return copy.deepcopy(DEFAULT_CONFIG)


def save_config(cfg):
    """Сохранить конфигурацию в файл."""
    # Normalize firmware_dirs to dict format before saving
    raw_dirs = cfg.get("firmware_dirs", DEFAULT_CONFIG["firmware_dirs"])
    normalized_dirs = normalize_firmware_dirs(raw_dirs)
    
    to_save = {
        "host": cfg.get("host", DEFAULT_CONFIG["host"]),
        "port": cfg.get("port", DEFAULT_CONFIG["port"]),
        "firmware_dirs": normalized_dirs,
        "manifest_path": cfg.get("manifest_path", DEFAULT_CONFIG["manifest_path"]),
        "manifest": cfg.get("manifest", DEFAULT_CONFIG["manifest"]),
        "device_username": cfg.get("device_username", DEFAULT_CONFIG["device_username"]),
        "device_password": cfg.get("device_password", DEFAULT_CONFIG["device_password"]),
        "device_http_port": cfg.get("device_http_port", DEFAULT_CONFIG["device_http_port"]),
        "backup": cfg.get("backup", DEFAULT_CONFIG["backup"]),
        "fs_update": cfg.get("fs_update", DEFAULT_CONFIG["fs_update"]),
        "udp_listener": cfg.get("udp_listener", DEFAULT_CONFIG["udp_listener"]),
        "traffic_light": cfg.get("traffic_light", DEFAULT_CONFIG["traffic_light"]),
        "logging": cfg.get("logging", DEFAULT_CONFIG["logging"])
    }
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(to_save, f, indent=4)
        return True
    except Exception as e:
        print(f"Error saving config: {e}")
        return False


def load_display_format():
    """Загрузить настройки отображения колонок."""
    if os.path.exists(DISPLAY_FORMAT_FILE):
        try:
            with open(DISPLAY_FORMAT_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading display format: {e}")
            return DEFAULT_DISPLAY_FORMAT.copy()
    return DEFAULT_DISPLAY_FORMAT.copy()


def save_display_format(fmt):
    """Сохранить настройки отображения колонок."""
    try:
        with open(DISPLAY_FORMAT_FILE, 'w') as f:
            json.dump(fmt, f, indent=4)
        return True
    except Exception as e:
        print(f"Error saving display format: {e}")
        return False


# ============================================================
# Бэкап конфигов и скриптов с устройств
# ============================================================

_BACKUP_LOCK = threading.Lock()
_BACKUP_STATE = {
    "running": False,
    "startedAt": None,
    "finishedAt": None,
    "total": 0,
    "done": 0,
    "current": "",
    "results": [],
    "error": None,
}


def _int_value(value, default, minimum=0):
    """Привести значение из JSON к int с ограничением снизу."""
    try:
        result = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, result)


def _sanitize_name(value, fallback=""):
    """Безопасное имя файла/папки (Unicode сохраняется)."""
    text = str(value or "").strip()
    text = re.sub(r'[<>:"/\\|?*\x00-\x1f]+', "_", text)
    text = re.sub(r"\s+", "_", text)
    text = text.strip(" .")
    if not text:
        return fallback
    if text.split(".")[0].upper() in _WINDOWS_RESERVED_NAMES:
        text = "_" + text
    return text[:64]

def _safe_rel_path(path):
    """Превратить путь внутри ФС устройства в безопасный относительный путь."""
    text = str(path or "").replace("\\", "/").strip()
    parts = []
    for segment in text.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            return None
        cleaned = _sanitize_name(segment, "")
        if not cleaned:
            continue
        parts.append(cleaned[:128])
    if not parts:
        return None
    return os.path.join(*parts)

def _unique_rel_path(rel_path, used):
    """Развести совпадающие относительные пути суффиксом _2, _3, ..."""
    key = rel_path.lower()
    if key not in used:
        used.add(key)
        return rel_path
    base, ext = os.path.splitext(rel_path)
    index = 2
    while f"{base}_{index}{ext}".lower() in used:
        index += 1
    result = f"{base}_{index}{ext}"
    used.add(result.lower())
    return result

def _validate_ip(ip):
    """Проверить, что IP — корректный IPv4-адрес."""
    try:
        addr = ipaddress.ip_address(str(ip or "").strip())
    except ValueError:
        return None
    if addr.version != 4:
        return None
    return str(addr)

def _parse_cvt(text):
    """Разобрать ответ /system/version формата key|value|div."""
    result = {}
    for line in (text or "").splitlines():
        parts = line.split("|")
        if len(parts) >= 2:
            result[parts[0].strip()] = parts[1].strip()
    return result

def _looks_like_html(data, headers=None):
    """Отличить HTML-страницу 404 от файла (ESP отдаёт её с кодом 200)."""
    content_type = ""
    if headers:
        content_type = str(headers.get("Content-Type") or "").lower()
    if "text/html" in content_type:
        return True
    head = (data or b"")[:512].lstrip().lower()
    return head.startswith(b"<!doctype html") or head.startswith(b"<html")

def _valid_json_bytes(data):
    """Проверить, что содержимое — валидный JSON."""
    try:
        json.loads((data or b"").decode("utf-8-sig"))
        return True
    except (UnicodeDecodeError, ValueError):
        return False

def _fetch_identity(ip, cfg, auth):
    """Вернуть (info, raw_text, error, fatal)."""
    try:
        resp = _device_get(ip, "/system/version", cfg, auth)
    except Exception as e:
        return {}, "", f"/system/version: {e}", True
    if resp.status_code == 200:
        raw = resp.text or ""
        return _parse_cvt(raw), raw, None, False
    if resp.status_code == 401:
        return {}, "", "HTTP 401: check device_username/device_password", True
    return {}, "", f"/system/version: HTTP {resp.status_code}", False

def _backup_delay(cfg):
    """Пауза между запросами к устройству."""
    delay_ms = cfg.get("delay_ms", 0)
    if delay_ms > 0:
        time.sleep(delay_ms / 1000.0)

def _write_file(root, rel_path, data):
    """Записать файл, не выходя за пределы корневой папки."""
    root_abs = os.path.abspath(root)
    dest = os.path.abspath(os.path.join(root_abs, rel_path))
    if os.path.commonpath([root_abs, dest]) != root_abs:
        raise ValueError(f"path escapes backup folder: {rel_path}")
    parent = os.path.dirname(dest)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(dest, "wb") as f:
        f.write(data)

def _write_json_file(root, rel_path, data):
    payload = json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")
    _write_file(root, rel_path, payload)

def _folder_owner_mac(folder_path):
    """MAC владельца существующей папки бэкапа (пусто, если meta нет)."""
    meta_path = os.path.join(folder_path, "meta.json")
    if not os.path.isfile(meta_path):
        return ""
    try:
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        device = meta.get("device") if isinstance(meta, dict) else None
        return str((device or {}).get("mac") or "").lower()
    except Exception:
        return ""

# ============================================================
# Версионные снимки (schema 2) и /fs API ядра
# ============================================================

def _device_auth():
    user = config.get("device_username") or ""
    password = config.get("device_password") or ""
    return (user, password) if user else None


def _cleanup_backup_staging(backup_root):
    if not os.path.isdir(backup_root):
        return
    for name in os.listdir(backup_root):
        if not (name.startswith(".incoming-") or name.startswith(".old-")):
            continue
        path = os.path.join(backup_root, name)
        if os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)


def _backup_settings():
    """Актуальные настройки бэкапов."""
    cfg = config.get("backup", {}) or {}
    base_dir = os.path.abspath(str(cfg.get("dir") or BACKUP_DEFAULT_DIR))
    return {
        "dir": base_dir,
        "timeout_s": _int_value(cfg.get("timeout_s"), BACKUP_DEFAULT_TIMEOUT_S, 1),
        "upload_timeout_s": _int_value(cfg.get("upload_timeout_s"),
                                        BACKUP_DEFAULT_UPLOAD_TIMEOUT_S, 1),
        "delay_ms": _int_value(cfg.get("inter_request_delay_ms"), BACKUP_DEFAULT_DELAY_MS, 0),
        "max_file_bytes": _int_value(cfg.get("max_file_bytes"),
                                     BACKUP_DEFAULT_MAX_FILE_BYTES, 1),
        "keep_manual": _int_value(cfg.get("keep_manual"), BACKUP_DEFAULT_KEEP_MANUAL, 0),
        "restore_verify": str(cfg.get("restore_verify") or "size").lower(),
        "include_patterns": [str(x) for x in (cfg.get("include_patterns")
                                               or BACKUP_DEFAULT_INCLUDE)],
        "exclude_patterns": [str(x) for x in (cfg.get("exclude_patterns")
                                               or BACKUP_DEFAULT_EXCLUDE)],
        "extra_config_files": cfg.get("extra_config_files") or [],
        "port": _int_value(config.get("device_http_port"), 80, 1),
    }


def _device_url(ip, path, cfg=None):
    port = _int_value((cfg or {}).get("port"), 80, 1)
    host = f"{ip}:{port}" if port != 80 else str(ip)
    if not str(path).startswith("/"):
        path = "/" + str(path)
    return f"http://{host}{path}"


def _device_get(ip, path, cfg, auth):
    timeout = cfg.get("timeout_s", BACKUP_DEFAULT_TIMEOUT_S)
    return requests.get(
        _device_url(ip, path, cfg),
        timeout=(min(5, timeout), timeout),
        auth=auth,
        headers={"Connection": "close"},
        allow_redirects=False,
    )


def _device_post(ip, path, cfg, auth, data=None, content_type=None, upload=False):
    timeout = cfg.get("upload_timeout_s" if upload else "timeout_s",
                      BACKUP_DEFAULT_UPLOAD_TIMEOUT_S if upload else BACKUP_DEFAULT_TIMEOUT_S)
    headers = {"Connection": "close"}
    if content_type:
        headers["Content-Type"] = content_type
    return requests.post(
        _device_url(ip, path, cfg),
        data=data,
        timeout=(min(5, timeout), timeout),
        auth=auth,
        headers=headers,
        allow_redirects=False,
    )


def _fetch_fs_info(ip, cfg, auth):
    """(info, error, fatal) для /fs/info."""
    try:
        resp = _device_get(ip, "/fs/info", cfg, auth)
    except Exception as e:
        return None, f"/fs/info: {e}", True
    if resp.status_code == 401:
        return None, "/fs/info: HTTP 401 (auth)", True
    if resp.status_code != 200:
        return None, f"/fs/info: HTTP {resp.status_code}", True
    if _looks_like_html(resp.content, resp.headers):
        return None, "/fs/info: HTML (core_fs not available)", True
    try:
        info = resp.json()
    except ValueError:
        return None, "/fs/info: invalid JSON", True
    if not isinstance(info, dict) or info.get("api") != CORE_FS_API_VERSION:
        return None, "/fs/info: unsupported api", True
    return info, None, False


def _fetch_fs_list(ip, cfg, auth):
    """(entries, info, error, fatal) для /fs/list."""
    try:
        resp = _device_get(ip, "/fs/list", cfg, auth)
    except Exception as e:
        return None, None, f"/fs/list: {e}", True
    if resp.status_code == 401:
        return None, None, "/fs/list: HTTP 401 (auth)", True
    if resp.status_code != 200:
        return None, None, f"/fs/list: HTTP {resp.status_code}", True
    if _looks_like_html(resp.content, resp.headers):
        return None, None, "/fs/list: HTML (core_fs not available)", True
    try:
        data = resp.json()
    except ValueError:
        return None, None, "/fs/list: invalid JSON", True
    if not isinstance(data, dict) or not isinstance(data.get("entries"), list):
        return None, None, "/fs/list: bad schema", True
    if data.get("count") != len(data.get("entries")):
        return None, None, "/fs/list: count mismatch", True
    if data.get("truncated"):
        return None, None, "/fs/list: truncated", True
    return data.get("entries"), data, None, False


def _select_snapshot_files(entries, cfg):
    include = cfg.get("include_patterns") or BACKUP_DEFAULT_INCLUDE
    exclude = cfg.get("exclude_patterns") or BACKUP_DEFAULT_EXCLUDE
    extra = set()
    for raw in cfg.get("extra_config_files") or []:
        if isinstance(raw, str) and raw.strip():
            path = "/" + raw.strip().lstrip("/")
            if path != "/_version_fs.json":
                extra.add(path)

    selected = []
    for entry in entries or []:
        if not isinstance(entry, dict) or entry.get("type") != "file":
            continue
        path = str(entry.get("path") or "")
        if not path.startswith("/") or ".." in path.split("/"):
            continue
        low = path.lower()
        if path not in extra:
            if not any(fnmatch.fnmatchcase(low, str(p).lower()) for p in include):
                continue
            if any(fnmatch.fnmatchcase(low, str(p).lower()) for p in exclude):
                continue
        selected.append(entry)
    selected.sort(key=lambda e: str(e.get("path") or ""))
    return selected


def _device_key(live, dev):
    name = _sanitize_name((live or {}).get("devicename") or dev.get("deviceName") or "")
    serial = _sanitize_name((live or {}).get("deviceserial") or dev.get("deviceSerial") or "")
    mac = str(dev.get("mac") or "")
    mac6 = re.sub(r"[^0-9A-Za-z]", "", mac)[-6:].upper() or "unknown"
    base = f"{name}_{serial}" if name and serial else (name or serial or f"device_{mac6}")
    base = base[:100].strip(" ._") or f"device_{mac6}"
    return f"{base}__{mac6}"


def _snapshot_target(backup_root, device_key, kind):
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    base = os.path.join(backup_root, device_key, f"{stamp}_{kind}")
    target = base
    index = 2
    while os.path.exists(target):
        target = f"{base}_{index}"
        index += 1
    return target


def _snapshot_id(backup_root, target):
    return os.path.relpath(target, backup_root).replace(os.sep, "/")


def _snapshot_paths_from_entries(entries):
    return [str(e.get("path")) for e in entries if e.get("type") == "file"]


def _snapshot_meta(backup_root, snapshot_id):
    """(path, meta) снимка; ValueError при неверном id."""
    parts = [p for p in str(snapshot_id or "").replace("\\", "/").split("/") if p]
    if len(parts) != 2 or any(p in (".", "..") for p in parts):
        raise ValueError("bad snapshot id")
    path = os.path.abspath(os.path.join(backup_root, parts[0], parts[1]))
    root = os.path.abspath(backup_root)
    if os.path.commonpath([root, path]) != root:
        raise ValueError("snapshot escapes root")
    meta_path = os.path.join(path, "meta.json")
    if not os.path.isfile(meta_path):
        raise ValueError("snapshot not found")
    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)
    if not isinstance(meta, dict) or meta.get("schema") != BACKUP_SCHEMA_VERSION:
        raise ValueError("unsupported snapshot schema")
    return path, meta


def _list_snapshots(backup_root):
    result = []
    if not os.path.isdir(backup_root):
        return result
    for device_key in sorted(os.listdir(backup_root)):
        if device_key.startswith("."):
            continue
        device_dir = os.path.join(backup_root, device_key)
        if not os.path.isdir(device_dir):
            continue
        for snap in sorted(os.listdir(device_dir)):
            if snap.startswith("."):
                continue
            snap_dir = os.path.join(device_dir, snap)
            if not os.path.isdir(snap_dir):
                continue
            meta_path = os.path.join(snap_dir, "meta.json")
            item = {
                "id": f"{device_key}/{snap}",
                "deviceKey": device_key,
                "snapshot": snap,
                "kind": "unknown",
                "createdAt": "",
                "device": {},
                "fsVersion": "",
                "fwVersion": "",
                "files": 0,
                "bytes": 0,
                "warnings": 0,
                "errors": 0,
                "broken": False,
            }
            try:
                with open(meta_path, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                if not isinstance(meta, dict):
                    raise ValueError("meta is not object")
                device = meta.get("device") or {}
                item.update({
                    "kind": meta.get("kind") or "unknown",
                    "createdAt": meta.get("createdAt") or "",
                    "device": device,
                    "fsVersion": str(device.get("versionfs") or ""),
                    "fwVersion": str(device.get("versionapp") or ""),
                    "files": len(meta.get("files") or []),
                    "bytes": sum(int(x.get("size") or 0) for x in (meta.get("files") or [])
                                 if isinstance(x, dict)),
                    "warnings": len(meta.get("warnings") or []),
                    "errors": len(meta.get("errors") or []),
                })
            except Exception as e:
                item["broken"] = True
                item["createdAt"] = datetime.fromtimestamp(
                    os.path.getmtime(snap_dir), timezone.utc).isoformat()
                item["device"] = {"error": str(e)}
            result.append(item)
    result.sort(key=lambda x: x.get("createdAt") or "", reverse=True)
    return result


def _prune_snapshots(backup_root, device_key, kind, keep):
    if keep <= 0:
        return
    device_dir = os.path.join(backup_root, device_key)
    if not os.path.isdir(device_dir):
        return
    snaps = []
    for name in os.listdir(device_dir):
        path = os.path.join(device_dir, name)
        if name.startswith(".") or not os.path.isdir(path):
            continue
        meta_path = os.path.join(path, "meta.json")
        created = ""
        snap_kind = ""
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
            created = str(meta.get("createdAt") or "")
            snap_kind = str(meta.get("kind") or "")
        except Exception:
            continue
        if snap_kind != kind:
            continue
        snaps.append((created, path))
    snaps.sort(reverse=True)
    for _, path in snaps[keep:]:
        shutil.rmtree(path, ignore_errors=True)


def _backup_one_device(dev, cfg, auth, backup_root, reserved=None,
                       kind="manual", preloaded=None):
    """Создать versioned-снимок одного устройства."""
    mac = str(dev.get("mac") or "")
    result = {
        "mac": mac,
        "deviceName": str(dev.get("deviceName") or ""),
        "deviceSerial": str(dev.get("deviceSerial") or ""),
        "ip": str(dev.get("ip") or ""),
        "deviceKey": "",
        "snapshot": "",
        "id": "",
        "folder": "",
        "kind": kind,
        "ok": False,
        "files": 0,
        "bytes": 0,
        "requests": 0,
        "missing": [],
        "warnings": [],
        "errors": [],
    }
    ip = _validate_ip(dev.get("ip"))
    if not ip:
        result["errors"].append("Invalid or empty IP")
        return result
    result["ip"] = ip

    raw_version = ""
    if preloaded:
        live = preloaded.get("live") or {}
        info = preloaded.get("info")
        entries = preloaded.get("entries")
        raw_version = preloaded.get("raw_version") or ""
    else:
        live, raw_version, identity_error, identity_fatal = _fetch_identity(ip, cfg, auth)
        result["requests"] += 1
        if identity_error and identity_fatal:
            result["errors"].append(identity_error)
            return result
        info, error, fatal = _fetch_fs_info(ip, cfg, auth)
        result["requests"] += 1
        if error:
            result["errors"].append(error)
            return result
        entries, _, error, fatal = _fetch_fs_list(ip, cfg, auth)
        result["requests"] += 1
        if error:
            result["errors"].append(error)
            return result

    device_key = _device_key(live, dev)
    result["deviceKey"] = device_key
    result["deviceName"] = str(live.get("devicename") or dev.get("deviceName") or "")
    result["deviceSerial"] = str(live.get("deviceserial") or dev.get("deviceSerial") or "")

    selected = _select_snapshot_files(entries, cfg)
    if not selected:
        result["errors"].append("No user files selected")
        return result

    staging = os.path.join(backup_root,
                           f".incoming-{device_key}-{os.getpid()}-{int(time.time() * 1000)}")
    os.makedirs(staging, exist_ok=False)
    stored = []
    used_rel = set()

    try:
        for entry in selected:
            path = str(entry.get("path") or "")
            size = int(entry.get("size") or 0)
            if size > cfg.get("max_file_bytes", BACKUP_DEFAULT_MAX_FILE_BYTES):
                result["errors"].append(f"{path}: too large ({size} bytes)")
                continue
            req_path = "/fs/download?path=" + quote(path, safe="")
            try:
                resp = _device_get(ip, req_path, cfg, auth)
                result["requests"] += 1
            except Exception as e:
                result["errors"].append(f"{path}: {e}")
                _backup_delay(cfg)
                continue
            if resp.status_code == 404:
                result["missing"].append(path)
                _backup_delay(cfg)
                continue
            if resp.status_code == 401:
                result["errors"].append(f"{path}: HTTP 401 (auth)")
                shutil.rmtree(staging, ignore_errors=True)
                return result
            if resp.status_code != 200:
                result["errors"].append(f"{path}: HTTP {resp.status_code}")
                _backup_delay(cfg)
                continue
            data = resp.content or b""
            rel = _safe_rel_path(path)
            if not rel:
                result["warnings"].append(f"{path}: skipped (bad path)")
                continue
            rel = _unique_rel_path(rel, used_rel)
            _write_file(staging, rel, data)
            stored.append({
                "path": path,
                "devicePath": path,
                "file": rel.replace(os.sep, "/"),
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            })
            result["files"] += 1
            result["bytes"] += len(data)
            _backup_delay(cfg)

        if result["files"] == 0:
            result["errors"].append("No files downloaded")
            shutil.rmtree(staging, ignore_errors=True)
            return result

        meta = {
            "schema": BACKUP_SCHEMA_VERSION,
            "kind": kind,
            "createdAt": datetime.now(timezone.utc).isoformat(),
            "deviceKey": device_key,
            "device": {
                "mac": mac,
                "name": result["deviceName"],
                "serial": result["deviceSerial"],
                "ip": ip,
                "target": str(dev.get("target") or ""),
                "espVer": str(dev.get("espVer") or ""),
                "versionapp": str(live.get("versionapp") or ""),
                "versionfs": str(live.get("versionfs") or ""),
                "buildenv": str(live.get("buildenv") or ""),
                "gitbranch": str(live.get("gitbranch") or ""),
                "gitcommit": str(live.get("gitcommit") or ""),
            },
            "systemVersionRaw": raw_version,
            "fsApi": CORE_FS_API_VERSION,
            "fsInfo": info,
            "fsList": {"count": len(entries), "truncated": False, "entries": entries},
            "files": stored,
            "missing": result["missing"],
            "warnings": result["warnings"],
            "errors": result["errors"],
            "stats": {
                "requests": result["requests"],
                "bytesRead": result["bytes"],
                "bytesWritten": 0,
                "durationMs": 0,
            },
        }
        _write_json_file(staging, "meta.json", meta)
        target = _snapshot_target(backup_root, device_key, kind)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        os.replace(staging, target)
        result["snapshot"] = target
        result["id"] = _snapshot_id(backup_root, target)
        result["folder"] = device_key
        result["ok"] = len(result["errors"]) == 0
        _prune_snapshots(backup_root, device_key, kind,
                         cfg.get("keep_manual" if kind == "manual" else "keep_snapshots", 0))
    except Exception as e:
        result["errors"].append(str(e))
        shutil.rmtree(staging, ignore_errors=True)
    return result


def _backup_state_snapshot():
    with _BACKUP_LOCK:
        return copy.deepcopy(_BACKUP_STATE)


def _backup_worker(devices, cfg, auth):
    total = len(devices)
    backup_root = cfg["dir"]
    reserved = set()
    fatal_error = None
    try:
        _broadcast_backup_event("backup_started", f"Backup started: {total} device(s)")
        for index, dev in enumerate(devices, 1):
            mac = str(dev.get("mac") or "")
            display_name = str(dev.get("deviceName") or mac)
            with _BACKUP_LOCK:
                _BACKUP_STATE["current"] = display_name
            try:
                result = _backup_one_device(dev, cfg, auth, backup_root, reserved)
            except Exception as e:
                result = {"mac": mac, "deviceName": display_name, "ok": False,
                          "files": 0, "bytes": 0, "errors": [str(e)]}
            with _BACKUP_LOCK:
                _BACKUP_STATE["done"] = index
                _BACKUP_STATE["results"].append(copy.deepcopy(result))
            errors = "; ".join(result.get("errors") or [])
            if result.get("ok"):
                message = f"[{index}/{total}] {display_name}: {result.get('files', 0)} file(s), {result.get('bytes', 0)} bytes -> {result.get('id', '')}"
            else:
                message = f"[{index}/{total}] {display_name}: error ({errors or 'unknown error'})"
            _broadcast_backup_event(
                "backup_device_done", message,
                device_mac=mac, device_name=display_name,
                folder=result.get("id", ""), ok=bool(result.get("ok")),
                files=result.get("files", 0), bytes=result.get("bytes", 0),
                error=errors,
            )
    except Exception as e:
        fatal_error = str(e)
    finally:
        with _BACKUP_LOCK:
            _BACKUP_STATE["running"] = False
            _BACKUP_STATE["current"] = ""
            _BACKUP_STATE["finishedAt"] = datetime.now(timezone.utc).isoformat()
            _BACKUP_STATE["error"] = fatal_error
            snapshot = copy.deepcopy(_BACKUP_STATE)
        ok_count = sum(1 for item in snapshot.get("results", []) if item.get("ok"))
        message = f"Backup finished: {ok_count}/{snapshot.get('total', total)} device(s) ok"
        _broadcast_backup_event("backup_finished", message,
                                ok=not fatal_error and ok_count == snapshot.get("total", total))


def _start_backup(macs):
    unique = []
    seen = set()
    for mac in macs:
        if not isinstance(mac, str):
            continue
        value = mac.strip()
        if not value or value in seen:
            continue
        seen.add(value)
        unique.append(value)
    if not unique:
        return None, "No MACs provided"
    devices = []
    unknown = []
    for mac in unique:
        device = device_storage.get_device_by_mac(mac)
        if device is None:
            unknown.append(mac)
        else:
            devices.append(device.to_dict())
    if unknown:
        return None, "Unknown device(s): " + ", ".join(unknown)
    with _BACKUP_LOCK:
        if _BACKUP_STATE["running"]:
            return None, "Backup already running"
        _BACKUP_STATE.update({
            "running": True, "startedAt": datetime.now(timezone.utc).isoformat(),
            "finishedAt": None, "total": len(devices), "done": 0, "current": "",
            "results": [], "error": None,
        })
    cfg = _backup_settings()
    auth = _device_auth()
    threading.Thread(target=_backup_worker, args=(devices, cfg, auth),
                     daemon=True, name="device-backup").start()
    return len(devices), None


# ============================================================
# Restore и FS-update
# ============================================================

def _broadcast_backup_event(event_type, message, **kwargs):
    payload = {
        "type": event_type,
        "message": message,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    payload.update(kwargs)
    try:
        sse_manager.broadcast(payload)
    except Exception:
        pass
    try:
        event_log.add(payload)
    except Exception:
        pass


_RESTORE_LOCK = threading.Lock()
_RESTORE_STATE = {"running": False, "startedAt": None, "finishedAt": None,
                  "current": "", "results": [], "error": None}
_FS_UPDATE_LOCK = threading.Lock()
_FS_UPDATE_STATE = {"running": False, "startedAt": None, "finishedAt": None,
                    "current": "", "results": [], "error": None}


def _restore_paths(meta):
    files = [f for f in (meta.get("files") or []) if isinstance(f, dict)]
    return sorted(files, key=lambda f: str(f.get("devicePath") or f.get("path") or ""))


def _restore_snapshot(dev, snapshot_dir, meta, cfg, auth):
    mac = str(dev.get("mac") or "")
    ip = _validate_ip(dev.get("ip"))
    result = {"mac": mac, "id": os.path.basename(os.path.dirname(snapshot_dir)) + "/" + os.path.basename(snapshot_dir),
              "ok": False, "files": 0, "bytes": 0, "requests": 0,
              "restored": [], "errors": [], "warnings": []}
    if not ip:
        result["errors"].append("Invalid or empty IP")
        return result
    snap_mac = str((meta.get("device") or {}).get("mac") or "").lower()
    if snap_mac and snap_mac != mac.lower():
        result["errors"].append("Snapshot belongs to another device")
        return result

    info, error, _ = _fetch_fs_info(ip, cfg, auth)
    result["requests"] += 1
    if error:
        result["errors"].append(error)
        return result

    files = _restore_paths(meta)
    restore = [f for f in files if not any(fnmatch.fnmatchcase(
        str(f.get("devicePath") or f.get("path") or "").lower(), str(p).lower())
        for p in (cfg.get("exclude_patterns") or []))]
    restore.sort(key=lambda f: 1 if str(f.get("devicePath") or f.get("path") or "").lower() == "/secret.json" else 0)

    needed = sum(int(f.get("size") or 0) for f in restore)
    if int(info.get("free") or 0) > 0 and needed > int(info.get("free") or 0):
        result["errors"].append("Not enough free space")
        return result

    for item in restore:
        device_path = str(item.get("devicePath") or item.get("path") or "")
        local_file = str(item.get("file") or "")
        target = os.path.abspath(os.path.join(snapshot_dir, local_file))
        if os.path.commonpath([os.path.abspath(snapshot_dir), target]) != os.path.abspath(snapshot_dir):
            result["errors"].append(f"{device_path}: bad local path")
            continue
        if not os.path.isfile(target):
            result["errors"].append(f"{device_path}: missing local file")
            continue
        with open(target, "rb") as f:
            data = f.read()
        try:
            resp = _device_post(ip, "/fs/upload?path=" + quote(device_path, safe=""),
                                cfg, auth, data=data,
                                content_type="application/octet-stream", upload=True)
            result["requests"] += 1
        except Exception as e:
            result["warnings"].append(f"{device_path}: {e}")
            continue
        if resp.status_code == 401:
            result["warnings"].append(f"{device_path}: HTTP 401 after restore")
        elif resp.status_code != 200:
            result["errors"].append(f"{device_path}: HTTP {resp.status_code}")
        else:
            result["files"] += 1
            result["bytes"] += len(data)
            result["restored"].append(device_path)
        _backup_delay(cfg)

    # Проверка размеров одним /fs/list (без пофайлового re-download).
    entries, _, error, _ = _fetch_fs_list(ip, cfg, auth)
    result["requests"] += 1
    if error:
        result["warnings"].append(f"verify: {error}")
    elif cfg.get("restore_verify") == "hash":
        by_path = {str(e.get("path")): e for e in entries if isinstance(e, dict)}
        for item in restore:
            device_path = str(item.get("devicePath") or item.get("path") or "")
            local_file = str(item.get("file") or "")
            target = os.path.join(snapshot_dir, local_file)
            if device_path not in by_path or not os.path.isfile(target):
                continue
            try:
                resp = _device_get(ip, "/fs/download?path=" + quote(device_path, safe=""),
                                   cfg, auth)
                result["requests"] += 1
                if resp.status_code == 200:
                    with open(target, "rb") as f:
                        expected = hashlib.sha256(f.read()).hexdigest()
                    if hashlib.sha256(resp.content).hexdigest() != expected:
                        result["errors"].append(f"{device_path}: hash mismatch")
            except Exception as e:
                result["warnings"].append(f"verify {device_path}: {e}")
    else:
        by_path = {str(e.get("path")): e for e in entries if isinstance(e, dict)}
        for item in restore:
            device_path = str(item.get("devicePath") or item.get("path") or "")
            found = by_path.get(device_path)
            if not found or int(found.get("size") or 0) != int(item.get("size") or 0):
                result["errors"].append(f"{device_path}: size verification failed")

    if cfg.get("restart_after_restore"):
        try:
            _device_post(ip, "/system/restart", cfg, auth)
        except Exception:
            pass

    result["ok"] = len(result["errors"]) == 0
    return result


def _restore_worker(items, cfg, auth):
    for dev, snapshot_dir, meta in items:
        name = str(dev.get("deviceName") or dev.get("mac") or "")
        with _RESTORE_LOCK:
            _RESTORE_STATE["current"] = name
        try:
            result = _restore_snapshot(dev, snapshot_dir, meta, cfg, auth)
        except Exception as e:
            result = {"mac": str(dev.get("mac") or ""), "ok": False,
                      "errors": [str(e)], "files": 0, "bytes": 0}
        with _RESTORE_LOCK:
            _RESTORE_STATE["results"].append(copy.deepcopy(result))
        _broadcast_backup_event("restore_device_done",
                                f"{name}: {'ok' if result.get('ok') else 'failed'}",
                                device_mac=result.get("mac", ""), device_name=name,
                                ok=bool(result.get("ok")), files=result.get("files", 0),
                                bytes=result.get("bytes", 0),
                                error="; ".join(result.get("errors") or []))
    with _RESTORE_LOCK:
        _RESTORE_STATE["running"] = False
        _RESTORE_STATE["finishedAt"] = datetime.now(timezone.utc).isoformat()
    _broadcast_backup_event("restore_finished", "Restore finished")


def _start_restore(items):
    with _RESTORE_LOCK:
        if _RESTORE_STATE["running"]:
            return None, "Restore already running"
        with _BACKUP_LOCK:
            if _BACKUP_STATE["running"]:
                return None, "Backup already running"
        with _FS_UPDATE_LOCK:
            if _FS_UPDATE_STATE["running"]:
                return None, "FS update already running"
        _RESTORE_STATE.update({
            "running": True, "startedAt": datetime.now(timezone.utc).isoformat(),
            "finishedAt": None, "current": "", "results": [], "error": None,
        })
    cfg = _backup_settings()
    cfg["restart_after_restore"] = bool(config.get("fs_update", {}).get(
        "restart_after_restore", True))
    threading.Thread(target=_restore_worker, args=(items, cfg, _device_auth()),
                     daemon=True, name="device-restore").start()
    return len(items), None


def _fetch_test_status(ip, cfg, auth):
    try:
        resp = _device_get(ip, "/otaclient/teststatus", cfg, auth)
        if resp.status_code != 200:
            return None
        return resp.json()
    except Exception:
        return None


def _fs_update_one(dev, cfg, auth):
    mac = str(dev.get("mac") or "")
    result = {"mac": mac, "deviceName": str(dev.get("deviceName") or mac),
              "stage": "start", "ok": False, "oldVersionFs": "",
              "newVersionFs": "", "snapshot": "", "errors": [], "warnings": []}
    ip = _validate_ip(dev.get("ip"))
    if not ip:
        result["errors"].append("Invalid or empty IP")
        return result

    live, _, identity_error, identity_fatal = _fetch_identity(ip, cfg, auth)
    if identity_error and identity_fatal:
        result["errors"].append(identity_error)
        return result
    info, error, _ = _fetch_fs_info(ip, cfg, auth)
    if error:
        result["errors"].append(error)
        return result
    entries, _, error, _ = _fetch_fs_list(ip, cfg, auth)
    if error:
        result["errors"].append(error)
        return result
    status = _fetch_test_status(ip, cfg, auth)
    if status is None:
        result["errors"].append("module_otaclient not available")
        return result

    result["oldVersionFs"] = str(live.get("versionfs") or "")
    result["stage"] = "snapshot"
    snapshot = _backup_one_device(dev, cfg, auth, cfg["dir"], kind="fs_update",
                                  preloaded={"live": live, "info": info,
                                             "entries": entries, "raw_version": ""})
    result["snapshot"] = snapshot.get("id", "")
    if not snapshot.get("ok") or not snapshot.get("id"):
        result["errors"].extend(snapshot.get("errors") or ["snapshot failed"])
        return result
    snapshot_dir = snapshot["snapshot"]
    meta_path = os.path.join(snapshot_dir, "meta.json")
    try:
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
    except Exception as e:
        result["errors"].append(f"snapshot meta: {e}")
        return result

    old_policy = (bool(dev.get("allowFwUpdate")), bool(dev.get("allowFsUpdate")))
    try:
        result["stage"] = "policy"
        device_storage.set_update_policy(mac, fw=False, fs=True)
        result["stage"] = "check"
        try:
            _device_post(ip, "/otaclient/test", cfg, auth)
        except Exception:
            pass
        deadline = time.time() + cfg.get("timeout_s", 10) * 6
        update_name = ""
        while time.time() < deadline:
            st = _fetch_test_status(ip, cfg, auth)
            code = (st or {}).get("code")
            update_name = str((st or {}).get("name") or "")
            if code == 4:
                break
            if code in (2, 3):
                break
            time.sleep(1)
        if not update_name or "-FILESYS-" not in update_name.upper():
            result["errors"].append("no FS update available")
            return result

        result["stage"] = "update"
        try:
            _device_post(ip, "/otaclient/update", cfg, auth)
        except Exception:
            pass

        result["stage"] = "wait_version"
        wait_deadline = time.time() + _int_value(
            (config.get("fs_update") or {}).get("reconnect_timeout_s"), 300, 10)
        poll = _int_value((config.get("fs_update") or {}).get("status_poll_s"), 3, 1)
        new_versionfs = ""
        while time.time() < wait_deadline:
            record = device_storage.get_device_by_mac(mac)
            if record is not None:
                ip = _validate_ip(record.ip) or ip
            live2, _, err2, fatal2 = _fetch_identity(ip, cfg, auth)
            if not err2 or not fatal2:
                new_versionfs = str(live2.get("versionfs") or "")
                if new_versionfs and new_versionfs != result["oldVersionFs"]:
                    break
            time.sleep(poll)
        result["newVersionFs"] = new_versionfs
        if not new_versionfs or new_versionfs == result["oldVersionFs"]:
            result["errors"].append("device did not return with new FS version")
            return result

        result["stage"] = "restore"
        restore = _restore_snapshot(dev, snapshot_dir, meta, cfg, auth)
        result["restore"] = restore
        if not restore.get("ok"):
            result["errors"].extend(restore.get("errors") or ["restore failed"])
        result["ok"] = len(result["errors"]) == 0
        result["stage"] = "done" if result["ok"] else "failed"
        return result
    finally:
        try:
            device_storage.set_update_policy(mac, fw=old_policy[0], fs=old_policy[1])
        except Exception:
            pass


def _fs_update_worker(devices, cfg, auth):
    for dev in devices:
        name = str(dev.get("deviceName") or dev.get("mac") or "")
        with _FS_UPDATE_LOCK:
            _FS_UPDATE_STATE["current"] = name
        try:
            result = _fs_update_one(dev, cfg, auth)
        except Exception as e:
            result = {"mac": str(dev.get("mac") or ""), "deviceName": name,
                      "stage": "failed", "ok": False, "errors": [str(e)]}
        with _FS_UPDATE_LOCK:
            _FS_UPDATE_STATE["results"].append(copy.deepcopy(result))
        _broadcast_backup_event("fs_update_device_done",
                                f"{name}: {result.get('stage')}",
                                device_mac=result.get("mac", ""), device_name=name,
                                ok=bool(result.get("ok")),
                                error="; ".join(result.get("errors") or []))
    with _FS_UPDATE_LOCK:
        _FS_UPDATE_STATE["running"] = False
        _FS_UPDATE_STATE["finishedAt"] = datetime.now(timezone.utc).isoformat()
    _broadcast_backup_event("fs_update_finished", "FS update job finished")


def _start_fs_update(macs):
    devices = []
    unknown = []
    for mac in macs or []:
        if not isinstance(mac, str):
            continue
        dev = device_storage.get_device_by_mac(mac.strip())
        if dev is None:
            unknown.append(mac)
        else:
            devices.append(dev.to_dict())
    if unknown:
        return None, "Unknown device(s): " + ", ".join(unknown)
    if not devices:
        return None, "No MACs provided"
    with _FS_UPDATE_LOCK:
        if _FS_UPDATE_STATE["running"]:
            return None, "FS update already running"
        with _BACKUP_LOCK:
            if _BACKUP_STATE["running"]:
                return None, "Backup already running"
        with _RESTORE_LOCK:
            if _RESTORE_STATE["running"]:
                return None, "Restore already running"
        _FS_UPDATE_STATE.update({
            "running": True, "startedAt": datetime.now(timezone.utc).isoformat(),
            "finishedAt": None, "current": "", "results": [], "error": None,
        })
    cfg = _backup_settings()
    fs_cfg = config.get("fs_update") or {}
    cfg["keep_snapshots"] = _int_value(fs_cfg.get("keep_snapshots"), 5, 0)
    cfg["restart_after_restore"] = bool(fs_cfg.get("restart_after_restore", True))
    threading.Thread(target=_fs_update_worker, args=(devices, cfg, _device_auth()),
                     daemon=True, name="device-fs-update").start()
    return len(devices), None


def _latest_snapshot_for_mac(backup_root, mac):
    wanted = str(mac or "").lower()
    for item in _list_snapshots(backup_root):
        device = item.get("device") or {}
        if str(device.get("mac") or "").lower() != wanted:
            continue
        try:
            path, meta = _snapshot_meta(backup_root, item["id"])
            return path, meta, item
        except Exception:
            continue
    return None, None, None


# ============================================================
# UDP-слушатель (аналог udpRxTx из udp.cs)
# ============================================================
class UdpListener:
    """
    UDP-слушатель в отдельном потоке.
    Аналог udpRxTx из example/udp.cs:
      - StartListening()  — асинхронный приём
      - udpReceive()      — обработка пакета
      - udpTxSimpleBroadcast()  — простая broadcast-отправка
      - udpTxSuperBroadcast()   — отправка по всем интерфейсам
    """

    def __init__(self, storage: DeviceStorage, sse_mgr: Optional['SseManager'] = None, event_log: Optional['EventLog'] = None):
        self._storage = storage
        self._sse_mgr = sse_mgr
        self._event_log = event_log
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._lock = threading.Lock()
        self._msg_count = 0

    # ---- Управление ----

    def start(self, port: int):
        """Запустить UDP-слушатель на указанном порту."""
        with self._lock:
            if self._running:
                self.stop()
            self._running = True
            self._thread = threading.Thread(
                target=self._listener_worker,
                args=(port,),
                daemon=True,
                name="udp-listener"
            )
            self._thread.start()
            print(f"UDP Listener started on port {port}")

    def stop(self):
        """Остановить UDP-слушатель."""
        with self._lock:
            self._running = False
            if self._sock:
                try:
                    self._sock.close()
                except:
                    pass
                self._sock = None
            if self._thread:
                self._thread.join(timeout=2)
                self._thread = None
            print("UDP Listener stopped")

    def restart(self, port: int):
        """Перезапустить слушатель (при изменении порта)."""
        self.stop()
        self.start(port)

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def msg_count(self) -> int:
        return self._msg_count

    # ---- Внутренний рабочий поток (аналог StartListening) ----

    def _listener_worker(self, port: int):
        """Фоновый поток: слушает UDP и обрабатывает пакеты."""
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Разрешаем broadcast (на всякий случай, хотя для приёма не обязательно)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self._sock.settimeout(1.0)  # таймаут для проверки _running
            self._sock.bind(('0.0.0.0', port))
            print(f"UDP Listener: bound to 0.0.0.0:{port}")
        except Exception as e:
            print(f"UDP Listener: FAILED to bind port {port}: {e}")
            self._running = False
            return

        keyword = config.get("udp_listener", {}).get("keyword", "Ave_Omnissiah")
        keyword_bytes = keyword.encode('utf-8')

        print(f"UDP Listener: waiting for packets (keyword='{keyword}')...")
        while self._running:
            try:
                data, addr = self._sock.recvfrom(2048)
                self._msg_count += 1
                print(f"UDP Listener: RX {len(data)} bytes from {addr[0]}:{addr[1]}")
                self._udp_receive(data, addr, keyword_bytes)
            except socket.timeout:
                continue
            except OSError as e:
                if self._running:
                    print(f"UDP Listener: socket error: {e}")
                break
            except Exception as e:
                print(f"UDP Listener: error: {e}")

        print("UDP Listener: thread stopped")
        self._running = False

    # ---- Обработка полученного пакета (аналог udpReceive) ----

    def _udp_receive(self, data: bytes, addr: tuple, keyword_bytes: bytes):
        """
        Обработка UDP-пакета от устройства.
        
        Устройство (ESP) отправляет broadcast с JSON вида:
          {"deviceName":"...", "keyword":"Ave_Omnissiah", ...}
        
        JSON не содержит keyword в начале сообщения — keyword находится
        внутри JSON-поля. Просто парсим JSON и проверяем поле keyword.
        
        Аналог udpReceive() из udp.cs, но без фильтрации по началу строки.
        """
        try:
            message = data.decode('utf-8').strip()
        except:
            return

        # Парсим JSON
        try:
            payload = json.loads(message)
        except json.JSONDecodeError:
            return

        # Проверяем, что это наше устройство — поле keyword должно совпадать
        expected_keyword = keyword_bytes.decode('utf-8')
        if payload.get("keyword", "") != expected_keyword:
            return

        # Проверяем наличие MAC — обязательное поле
        if not payload.get("mac"):
            return

        # Обновляем устройство в хранилище
        dev, is_new = self._storage.update_device(payload)

        if dev:
            # Отвечаем устройству ACK (unicast на его udpPortRx из payload),
            # чтобы устройство запомнило IP сервера и перестало бродкастить.
            try:
                ack_msg = json.dumps({"keyword": expected_keyword, "ack": True})
                ack_port = int(payload.get("udpPortRx", 0) or 0)
                if not (1024 <= ack_port <= 65535):
                    ack_port = addr[1]
                self.udp_tx_unicast(ack_msg, addr[0], ack_port)
                print(f"UDP Listener: ACK -> {addr[0]}:{ack_port}")
            except Exception as e:
                print(f"UDP Listener: ACK error: {e}")

        # Формируем событие для SSE и лога
        if dev:
            device_name = dev.deviceName or "Unknown"
            mac_short = dev.mac[-8:] if len(dev.mac) > 8 else dev.mac
            event_type = "device_created" if is_new else "device_updated"
            message_text = (
                f"[{device_name}] MAC:...{mac_short} | "
                f"IP: {dev.ip} | FW: {dev.espVer or '?'} | "
                f"Target: {dev.target or '?'}"
            )

            event_data = {
                "type": event_type,
                "message": message_text,
                "device_mac": dev.mac,
                "device_name": device_name,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }

            # Добавляем в лог
            if self._event_log:
                self._event_log.add(event_data)

            # Рассылаем SSE
            if self._sse_mgr:
                self._sse_mgr.broadcast(event_data)

    # ---- Простая broadcast-отправка (аналог udpTxSimpleBroadcast) ----

    def udp_tx_simple_broadcast(self, message: str, port: int):
        """
        Отправить broadcast-сообщение на указанный порт.
        Аналог udpTxSimpleBroadcast() из udp.cs.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.settimeout(2.0)
            data = message.encode('utf-8')
            sock.sendto(data, ('255.255.255.255', port))
            sock.close()
        except Exception as e:
            print(f"UDP simple broadcast error: {e}")

    # ---- Unicast-отправка (аналог ACK устройству) ----

    def udp_tx_unicast(self, message: str, ip: str, port: int):
        """
        Отправить unicast-сообщение конкретному устройству.
        Используется для ACK в ответ на телеметрию устройства.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0)
            data = message.encode('utf-8')
            sock.sendto(data, (ip, port))
            sock.close()
        except Exception as e:
            print(f"UDP unicast error: {e}")

    # ---- Super-broadcast (аналог udpTxSuperBroadcast) ----

    def udp_tx_super_broadcast(self, message: str, port: int):
        """
        Отправить broadcast по всем сетевым интерфейсам.
        Аналог udpTxSuperBroadcast() из udp.cs.
        Перебирает все сетевые интерфейсы с IPv4 и отправляет broadcast.
        """
        import netifaces

        sent_count = 0
        try:
            interfaces = netifaces.interfaces()
        except Exception as e:
            print(f"Super broadcast: netifaces error: {e}, fallback to simple broadcast")
            self.udp_tx_simple_broadcast(message, port)
            return

        data = message.encode('utf-8')

        for iface in interfaces:
            try:
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET not in addrs:
                    continue
                for addr_info in addrs[netifaces.AF_INET]:
                    ip = addr_info.get('addr', '')
                    broadcast = addr_info.get('broadcast', '')

                    # Пропускаем loopback
                    if ip == '127.0.0.1' or ip.startswith('127.'):
                        continue

                    if not broadcast:
                        continue

                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_DONTROUTE, 1)
                        sock.bind((ip, 0))
                        sock.sendto(data, (broadcast, port))
                        sock.close()
                        sent_count += 1
                    except:
                        continue
            except:
                continue

        # Если ни один интерфейс не отправил (нет broadcast-адресов) — пробуем глобальный broadcast
        if sent_count == 0:
            self.udp_tx_simple_broadcast(message, port)
            sent_count += 1

        print(f"Super broadcast: sent {sent_count} packets on port {port}")
        return sent_count


# ============================================================
# Инициализация
# ============================================================
config = load_config()
display_format = load_display_format()

# Применить настройки файловых логов (папка + вкл/выкл)
if not TEST_MODE:
    apply_logging_config(config.get("logging", DEFAULT_CONFIG["logging"]))
if log_tee.enabled:
    log_dir = config.get("logging", {}).get("directory", "log")
    print(f"File logging enabled: logs are saved to '{os.path.join(log_dir, 'otasyncer_YYYYMMDD_HHMMSS.log')}' (hourly rotation)")

device_storage = DeviceStorage(DEVICES_DB_FILE)
event_log = EventLog()
sse_manager = SseManager()
udp_listener = UdpListener(device_storage, sse_mgr=sse_manager, event_log=event_log)

# Запуск UDP-слушателя
udp_cfg = config.get("udp_listener", {})
if udp_cfg.get("is_listening", True) and not TEST_MODE:
    udp_listener.start(udp_cfg.get("receive_port", 40000))


def _startup_probe_worker():
    """
    Фоновый поток: при старте сервера шлёт 2-3 probe-бродкаста,
    чтобы устройства услышали сервер, ответили и запомнили его IP
    (настройка probe_devices_on_startup, по умолчанию включена).
    """
    try:
        if not config.get("udp_listener", {}).get("probe_devices_on_startup", True):
            return
        keyword = config.get("udp_listener", {}).get("keyword", "Ave_Omnissiah")
        port = config.get("udp_listener", {}).get("transmit_port", 40001)
        time.sleep(2)  # дать сокету привязаться
        for i in range(3):
            if not udp_listener.is_running:
                break
            count = udp_listener.udp_tx_super_broadcast(keyword, port)
            print(f"Startup probe {i + 1}/3: keyword='{keyword}' port={port} sent={count}")
            time.sleep(2)
    except Exception as e:
        print(f"Startup probe error: {e}")


if config.get("udp_listener", {}).get("probe_devices_on_startup", True) and not TEST_MODE:
    startup_probe_thread = threading.Thread(
        target=_startup_probe_worker, daemon=True, name="udp-startup-probe"
    )
    startup_probe_thread.start()

# Ensure all firmware dirs exist
for entry in config["firmware_dirs"]:
    dir_path = entry["path"] if isinstance(entry, dict) else entry
    os.makedirs(dir_path, exist_ok=True)

# Каталог бэкапов и очистка незавершённых staging-папок
try:
    _backup_root = os.path.abspath(_backup_settings()["dir"])
    _cleanup_backup_staging(_backup_root)
except Exception as e:
    print(f"Backup init error: {e}")


# ============================================================
# Периодическая очистка офлайн-устройств
# ============================================================
def _periodic_cleanup():
    """Фоновый поток: периодически помечает устройства офлайн и чистит старые."""
    while True:
        time.sleep(60)  # каждую минуту
        try:
            device_storage.mark_offline()
            device_storage.cleanup_old()
        except Exception as e:
            print(f"Cleanup error: {e}")

if not TEST_MODE:
    cleanup_thread = threading.Thread(target=_periodic_cleanup, daemon=True, name="device-cleanup")
    cleanup_thread.start()


# ============================================================
# Утилиты для прошивок
# ============================================================
def calculate_md5(filepath):
    """Calculates the MD5 hash of a given file."""
    if not os.path.exists(filepath):
        return None
    md5 = hashlib.md5()
    try:
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b""):
                md5.update(chunk)
        return md5.hexdigest()
    except Exception as e:
        print(f"Error calculating MD5 for {filepath}: {e}")
        return None


def get_file_type(filename):
    """Determine file type from filename: 'firmware' or 'filesystem'.
    
    New format:
        Test32Ota-FIRMWARE-0.021.20260521_2135.0711.bin  -> firmware
        Test32Ota-FILESYS-0.021.20260521_2135.0711.bin   -> filesystem
    
    Old format (no longer generated, but ignored gracefully):
        Test32Ota-0.021.20260521_2135.0711.bin            -> unknown
        Test32Ota_fs-0.021.20260521_2135.0711.bin         -> unknown
    """
    if "-FILESYS-" in filename:
        return "filesystem"
    elif "-FIRMWARE-" in filename:
        return "firmware"
    else:
        return "unknown"


def scan_firmware_files():
    """Scan all firmware directories and return list of file entries."""
    entries = []
    for entry in config["firmware_dirs"]:
        dir_path = entry["path"] if isinstance(entry, dict) else entry
        if not os.path.exists(dir_path):
            continue
        for fname in os.listdir(dir_path):
            if not fname.endswith('.bin'):
                continue
            fpath = os.path.join(dir_path, fname)
            if not os.path.isfile(fpath):
                continue

            size = os.path.getsize(fpath)
            md5 = calculate_md5(fpath)

            entries.append({
                "name": fname,
                "type": get_file_type(fname),
                "size": size,
                "md5": md5 or "",
                "dir": os.path.abspath(dir_path)
            })

    return entries


def get_file_status():
    """Get status info for admin interface."""
    entries = scan_firmware_files()
    total_files = len(entries)
    total_size = sum(e["size"] for e in entries)
    return {
        "total_files": total_files,
        "total_size": f"{total_size / 1024:.2f} KB" if total_size > 0 else "0 KB",
        "files": entries
    }


def find_file_in_dirs(filename):
    """Search for a file across all firmware dirs, return full path or None."""
    safe_name = secure_filename(filename)
    for entry in config["firmware_dirs"]:
        dir_path = entry["path"] if isinstance(entry, dict) else entry
        candidate = os.path.join(dir_path, safe_name)
        if os.path.exists(candidate):
            return candidate
    return None


def parse_firmware_filename(filename):
    """
    Parse a firmware filename and extract components.
    
    Format: {env_name}-{TYPE}-{MAJOR}.{MINOR}.{DATE}_{TIME}.{BUILD}.bin
    
    Returns dict with keys: prefix (env_name-TYPE), version_str, or None if unparseable.
    """
    import re
    # Pattern: <env_name>-FIRMWARE-<version>.bin or <env_name>-FILESYS-<version>.bin
    match = re.match(r'^(.+-(?:FIRMWARE|FILESYS))-(\d+\.\d+\.\d+_\d+\.\d+)\.bin$', filename)
    if match:
        return {
            "prefix": match.group(1),
            "version_str": match.group(2)
        }
    return None


def version_to_sort_key(version_str):
    """
    Convert version string '0.022.20260525_1209.0744' to a tuple for comparison.
    Higher tuple = newer version.
    """
    try:
        parts = version_str.split('.')
        major = int(parts[0])
        minor = int(parts[1])
        # date_time part: '20260525_1209' -> remove underscore for numeric compare
        date_part = parts[2].replace('_', '')
        date_val = int(date_part)
        build = int(parts[3])
        return (major, minor, date_val, build)
    except (IndexError, ValueError):
        return None


def remove_old_versions(filepath):
    """
    When a new firmware file appears, remove older versions of the same
    firmware type (same env_name + FIRMWARE/FILESYS prefix) from the same directory.
    
    Only works if the filename follows the standard format:
        {env_name}-{TYPE}-{MAJOR}.{MINOR}.{DATE}_{TIME}.{BUILD}.bin
    
    Returns list of removed file paths.
    """
    dir_path = os.path.dirname(filepath)
    filename = os.path.basename(filepath)
    
    parsed = parse_firmware_filename(filename)
    if not parsed:
        return []
    
    prefix = parsed["prefix"]
    new_version_key = version_to_sort_key(parsed["version_str"])
    if new_version_key is None:
        return []
    
    removed = []
    for fname in os.listdir(dir_path):
        if fname == filename:
            continue
        if not fname.endswith('.bin'):
            continue
        
        other_parsed = parse_firmware_filename(fname)
        if not other_parsed:
            continue
        
        # Same prefix (same env_name + type) -> candidate for removal
        if other_parsed["prefix"] != prefix:
            continue
        
        other_version_key = version_to_sort_key(other_parsed["version_str"])
        if other_version_key is None:
            continue
        
        # If the other file is older (smaller version key), delete it
        if other_version_key < new_version_key:
            other_path = os.path.join(dir_path, fname)
            try:
                os.remove(other_path)
                removed.append(other_path)
                print(f"Removed old version: {other_path}")
            except Exception as e:
                print(f"Error removing old version {other_path}: {e}")
    
    return removed


def cleanup_dir_old_versions(dir_path):
    """
    Scan a directory and remove older versions of firmware files,
    keeping only the newest version for each (env_name + TYPE) prefix.
    
    Returns dict with prefix -> list of removed file paths.
    """
    if not os.path.isdir(dir_path):
        return {}
    
    # Group files by prefix
    groups = {}  # prefix -> [(filename, version_key), ...]
    for fname in os.listdir(dir_path):
        if not fname.endswith('.bin'):
            continue
        parsed = parse_firmware_filename(fname)
        if not parsed:
            continue
        vkey = version_to_sort_key(parsed["version_str"])
        if vkey is None:
            continue
        prefix = parsed["prefix"]
        if prefix not in groups:
            groups[prefix] = []
        groups[prefix].append((fname, vkey))
    
    # For each group, keep only the newest, remove the rest
    results = {}
    for prefix, files in groups.items():
        if len(files) <= 1:
            continue
        # Sort by version key descending, keep first (newest)
        files.sort(key=lambda x: x[1], reverse=True)
        newest = files[0][0]
        removed = []
        for fname, _ in files[1:]:
            fpath = os.path.join(dir_path, fname)
            try:
                os.remove(fpath)
                removed.append(fpath)
                print(f"Cleanup removed old version: {fpath}")
            except Exception as e:
                print(f"Error removing {fpath}: {e}")
        if removed:
            results[prefix] = removed
    
    return results


# ============================================================
# Flask Routes — Главная
# ============================================================
@app.route('/', methods=['GET'])
def index():
    """Admin interface."""
    status = get_file_status()
    message = request.args.get('message')
    return render_template('index.html',
        status=status,
        firmware_dirs=config["firmware_dirs"],
        message=message,
        device_count=device_storage.get_total_count(),
        device_online=device_storage.get_online_count()
    )


@app.route('/upload', methods=['POST'])
def upload_firmware():
    """Handle file upload."""
    if 'file' not in request.files:
        return redirect(url_for('index', message='Error: No file part in the request.'))

    file = request.files['file']
    if file.filename == '':
        return redirect(url_for('index', message='Error: No selected file.'))

    if file:
        filename = secure_filename(file.filename)
        if not filename.endswith('.bin'):
            return redirect(url_for('index', message='Error: Only .bin files are allowed.'))

        first_entry = config["firmware_dirs"][0] if config["firmware_dirs"] else {"path": "./firmware", "delete_old_versions": False}
        target_dir = first_entry["path"] if isinstance(first_entry, dict) else first_entry
        delete_old = first_entry.get("delete_old_versions", False) if isinstance(first_entry, dict) else False

        os.makedirs(target_dir, exist_ok=True)
        filepath = os.path.join(target_dir, filename)
        try:
            file.save(filepath)
            md5 = calculate_md5(filepath)

            # Remove old versions if enabled for this directory
            removed_count = 0
            if delete_old:
                removed = remove_old_versions(filepath)
                removed_count = len(removed)

            msg = f"Success! Uploaded '{filename}' to {target_dir} (MD5: {md5})"
            if removed_count > 0:
                msg += f" | Removed {removed_count} old version(s)"

            return redirect(url_for('index', message=msg))
        except Exception as e:
            return redirect(url_for('index', message=f"Upload Failed: {str(e)}"))


@app.route('/delete/<filename>', methods=['POST'])
def delete_firmware(filename):
    """Delete a firmware file."""
    safe_name = secure_filename(filename)
    filepath = find_file_in_dirs(safe_name)
    try:
        if filepath and os.path.exists(filepath):
            os.remove(filepath)
            return redirect(url_for('index', message=f"Deleted '{safe_name}'"))
        return redirect(url_for('index', message=f"Error: File '{safe_name}' not found."))
    except Exception as e:
        return redirect(url_for('index', message=f"Delete Failed: {str(e)}"))


@app.route('/manifest.json')
def manifest():
    """Generate manifest.json for OTA client devices.

    Сервер сам решает, какие типы обновлений разрешены конкретному устройству:
      — если тип запрещён — файлы этого типа в манифест не попадают;
      — если тип разрешён — попадает только один самый свежий файл этого типа.

    Query parameters:
      target (str)  — BUILD_ENV устройства (обязательный)
      ver (str)     — текущая версия прошивки устройства (опционально, для лога)
      mac (str)     — MAC устройства (опционально, для точной идентификации)

    Returns:
      files (list)     — до одного самого свежего файла каждого разрешённого типа
                         (FIRMWARE + FILESYS)
      has_files (bool) — true если для этого устройства есть разрешённые файлы
    """
    target = request.args.get('target', '')

    if not target:
        return jsonify({"files": [], "has_files": False})

    entries = scan_firmware_files()

    # Separate by type and assign sort keys
    firmware = []
    filesys = []

    for e in entries:
        if e["type"] == "unknown":
            continue
        if not e["name"].startswith(target):
            continue

        parsed = parse_firmware_filename(e["name"])
        if parsed:
            vkey = version_to_sort_key(parsed["version_str"])
            sort_key = vkey if vkey else (0, 0, 0, 0)
        else:
            sort_key = (0, 0, 0, 0)

        entry = {
            "name": e["name"],
            "type": e["type"],
            "size": e["size"],
            "md5": e["md5"],
            "_sort_key": sort_key
        }

        if e["type"] == "firmware":
            firmware.append(entry)
        elif e["type"] == "filesystem":
            filesys.append(entry)

    # Sort newest first
    firmware.sort(key=lambda x: x["_sort_key"], reverse=True)
    filesys.sort(key=lambda x: x["_sort_key"], reverse=True)

    # Определяем устройство и его разрешения на обновление.
    # Приоритет: mac из запроса, затем сопоставление по IP источника.
    mac_q = (request.args.get('mac') or '').strip().upper()
    dev = device_storage.get_device_by_mac(mac_q) if mac_q else None
    if dev is None:
        dev = device_storage.find_device_for_update(request.remote_addr or '', target)

    if dev:
        allow_fw = bool(dev.allowFwUpdate)
        allow_fs = bool(dev.allowFsUpdate)
        print(f"Manifest for {target} from {request.remote_addr}: {dev.mac} "
              f"(fw={allow_fw}, fs={allow_fs})")
    else:
        # Устройство не найдено — применяем политику по умолчанию: всё запрещено.
        allow_fw = False
        allow_fs = False

    # Сервер отдаёт ровно один самый свежий файл каждого разрешённого типа
    def strip_key(entry):
        return {"name": entry["name"], "type": entry["type"],
                "size": entry["size"], "md5": entry["md5"]}

    result = []
    if allow_fw and firmware:
        result.append(strip_key(firmware[0]))
    if allow_fs and filesys:
        result.append(strip_key(filesys[0]))

    return jsonify({
        "files": result,
        "has_files": len(result) > 0
    })


@app.route('/firmware/<path:filename>')
def download_firmware(filename):
    """Download a firmware binary."""
    safe_name = secure_filename(filename)
    filepath = find_file_in_dirs(safe_name)
    if not filepath:
        return jsonify({"error": "File not found"}), 404

    return send_file(
        filepath,
        mimetype='application/octet-stream',
        as_attachment=True,
        download_name=safe_name
    )


# ============================================================
# Flask Routes — Конфигурация прошивок
# ============================================================
@app.route('/config', methods=['GET'])
def get_config():
    """Return current config as JSON."""
    return jsonify({
        "host": config["host"],
        "port": config["port"],
        "firmware_dirs": config["firmware_dirs"],
        "manifest_path": config["manifest_path"],
        "device_username": config.get("device_username", ""),
        "device_password_configured": bool(config.get("device_password")),
        "backup": config.get("backup", {}),
        "udp_listener": config.get("udp_listener", {}),
        "traffic_light": config.get("traffic_light", {}),
        "logging": config.get("logging", {})
    })


@app.route('/config/dirs', methods=['POST'])
def update_dirs():
    """Update firmware_dirs list."""
    try:
        data = request.get_json(force=True)
        if not data or "firmware_dirs" not in data:
            return jsonify({"success": False, "error": "Missing firmware_dirs"}), 400

        new_dirs = data["firmware_dirs"]
        if not isinstance(new_dirs, list) or len(new_dirs) == 0:
            return jsonify({"success": False, "error": "firmware_dirs must be a non-empty list"}), 400

        # Normalize to dict format (support both old string format and new dict format)
        normalized = normalize_firmware_dirs(new_dirs)

        # Ensure all directories exist
        for entry in normalized:
            os.makedirs(entry["path"], exist_ok=True)

        config["firmware_dirs"] = normalized
        save_config(config)

        # Run cleanup for directories with delete_old_versions enabled
        cleanup_results = {}
        for entry in normalized:
            if entry.get("delete_old_versions", False):
                result = cleanup_dir_old_versions(entry["path"])
                if result:
                    cleanup_results[entry["path"]] = result

        return jsonify({
            "success": True,
            "firmware_dirs": config["firmware_dirs"],
            "cleanup_results": cleanup_results
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================================
# Flask Routes — Устройства (Devices)
# ============================================================
@app.route('/devices', methods=['GET'])
def devices_page():
    """Страница со списком устройств."""
    display = load_display_format()
    return render_template('devices.html',
        display_format=display,
        device_count=device_storage.get_total_count(),
        device_online=device_storage.get_online_count()
    )


@app.route('/api/devices/clear', methods=['POST'])
def api_devices_clear():
    """API: очистить список всех устройств."""
    try:
        device_storage.clear_all()
        event_log.clear()

        # Отправляем SSE-событие об очистке
        event_data = {
            "type": "devices_cleared",
            "message": "All devices have been cleared",
            "device_mac": "",
            "device_name": "",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        event_log.add(event_data)
        sse_manager.broadcast(event_data)

        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/events', methods=['GET'])
def api_events():
    """SSE endpoint: поток событий в реальном времени."""
    def generate():
        q = sse_manager.subscribe()
        try:
            while True:
                event_data = q.get()  # блокируется до появления события
                data_json = json.dumps(event_data)
                yield f"data: {data_json}\n\n"
        except GeneratorExit:
            pass
        finally:
            sse_manager.unsubscribe(q)

    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no',
        }
    )


@app.route('/api/events/log', methods=['GET'])
def api_events_log():
    """API: получить историю событий лога."""
    return jsonify({"events": event_log.get_all()})


@app.route('/api/devices', methods=['GET'])
def api_devices():
    """API: список устройств. ?minutes=N — фильтр по времени."""
    minutes = request.args.get('minutes', 0, type=int)
    if minutes > 0:
        devices = device_storage.get_devices_since(minutes)
    else:
        devices = device_storage.get_all_devices()

    return jsonify({
        "total": len(devices),
        "online": sum(1 for d in devices if d.isOnline),
        "devices": [d.to_dict() for d in devices]
    })


@app.route('/api/device/<mac>', methods=['GET'])
def api_device(mac):
    """API: информация об одном устройстве по MAC."""
    dev = device_storage.get_device_by_mac(mac)
    if not dev:
        return jsonify({"error": "Device not found"}), 404
    return jsonify(dev.to_dict())


@app.route('/api/device/<mac>/update-policy', methods=['POST'])
def api_device_update_policy(mac):
    """
    API: установить разрешения на автообновление устройства.
    Тело: {"allowFwUpdate": true/false, "allowFsUpdate": true/false} — поля частичные.
    """
    try:
        data = request.get_json(force=True) if request.is_json else None
        if not data:
            return jsonify({"success": False, "error": "No data"}), 400

        dev = device_storage.set_update_policy(
            mac,
            fw=data.get("allowFwUpdate"),
            fs=data.get("allowFsUpdate")
        )
        if dev is None:
            return jsonify({"success": False, "error": "Device not found"}), 404

        print(f"Update policy for {mac}: allowFwUpdate={dev.allowFwUpdate}, allowFsUpdate={dev.allowFsUpdate}")
        return jsonify({"success": True, "device": dev.to_dict()})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/devices/backup', methods=['POST'])
def api_devices_backup():
    """API: запустить фоновый бэкап выбранных устройств."""
    try:
        data = request.get_json(force=True, silent=True) or {}
        macs = data.get("macs")
        if not isinstance(macs, list) or not macs:
            return jsonify({"success": False, "error": "macs must be a non-empty list"}), 400

        count, error = _start_backup(macs)
        if error:
            status = 409 if error == "Backup already running" else 400
            return jsonify({"success": False, "error": error}), status
        return jsonify({"success": True, "total": count}), 202
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/devices/backup/status', methods=['GET'])
def api_devices_backup_status():
    """API: состояние текущего/последнего бэкапа."""
    return jsonify({"success": True, "state": _backup_state_snapshot()})


# ============================================================
# Flask Routes — версионные снимки / восстановление / FS-update
# ============================================================
@app.route('/backups', methods=['GET'])
def backups_page():
    return render_template('backups.html')


@app.route('/api/backups', methods=['GET'])
def api_backups_list():
    try:
        root = _backup_settings()["dir"]
        items = _list_snapshots(root)
        mac = str(request.args.get("mac") or "").lower()
        device = str(request.args.get("device") or "").lower()
        kind = str(request.args.get("kind") or "").lower()
        if mac:
            items = [x for x in items
                     if str((x.get("device") or {}).get("mac") or "").lower() == mac]
        if device:
            items = [x for x in items if str(x.get("deviceKey") or "").lower() == device]
        if kind:
            items = [x for x in items if str(x.get("kind") or "").lower() == kind]
        return jsonify({"success": True, "backups": items})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/backups/<path:backup_id>', methods=['GET'])
def api_backups_detail(backup_id):
    try:
        root = _backup_settings()["dir"]
        path, meta = _snapshot_meta(root, backup_id)
        return jsonify({"success": True, "id": backup_id, "path": path, "meta": meta})
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 404
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/backups/<path:backup_id>/file', methods=['GET'])
def api_backups_file(backup_id):
    try:
        root = _backup_settings()["dir"]
        path, meta = _snapshot_meta(root, backup_id)
        wanted = str(request.args.get("path") or "")
        for item in meta.get("files") or []:
            if not isinstance(item, dict):
                continue
            device_path = str(item.get("devicePath") or item.get("path") or "")
            if device_path != wanted:
                continue
            local = os.path.abspath(os.path.join(path, str(item.get("file") or "")))
            if os.path.commonpath([os.path.abspath(path), local]) != os.path.abspath(path):
                return jsonify({"success": False, "error": "bad path"}), 400
            if not os.path.isfile(local):
                return jsonify({"success": False, "error": "file not found"}), 404
            return send_file(local, as_attachment=True,
                             download_name=os.path.basename(device_path))
        return jsonify({"success": False, "error": "file not found"}), 404
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 404
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/backups/<path:backup_id>', methods=['DELETE'])
def api_backups_delete(backup_id):
    try:
        root = _backup_settings()["dir"]
        path, _ = _snapshot_meta(root, backup_id)
        with _RESTORE_LOCK:
            if _RESTORE_STATE.get("running"):
                return jsonify({"success": False, "error": "restore running"}), 409
        with _FS_UPDATE_LOCK:
            if _FS_UPDATE_STATE.get("running"):
                return jsonify({"success": False, "error": "FS update running"}), 409
        shutil.rmtree(path, ignore_errors=False)
        return jsonify({"success": True})
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 404
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/backups/delete', methods=['POST'])
def api_backups_delete_bulk():
    try:
        data = request.get_json(force=True, silent=True) or {}
        ids = data.get("ids")
        if not isinstance(ids, list) or not ids:
            return jsonify({"success": False, "error": "ids must be a non-empty list"}), 400
        with _RESTORE_LOCK:
            if _RESTORE_STATE.get("running"):
                return jsonify({"success": False, "error": "restore running"}), 409
        with _FS_UPDATE_LOCK:
            if _FS_UPDATE_STATE.get("running"):
                return jsonify({"success": False, "error": "FS update running"}), 409
        root = _backup_settings()["dir"]
        deleted = []
        for backup_id in ids:
            try:
                path, _ = _snapshot_meta(root, str(backup_id))
                shutil.rmtree(path, ignore_errors=False)
                deleted.append(str(backup_id))
            except Exception:
                continue
        return jsonify({"success": True, "deleted": deleted})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/backups/<path:backup_id>/restore', methods=['POST'])
def api_backups_restore(backup_id):
    try:
        root = _backup_settings()["dir"]
        path, meta = _snapshot_meta(root, backup_id)
        mac = str((meta.get("device") or {}).get("mac") or "")
        record = device_storage.get_device_by_mac(mac)
        if record is None:
            return jsonify({"success": False, "error": "Device not found"}), 404
        count, error = _start_restore([(record.to_dict(), path, meta)])
        if error:
            return jsonify({"success": False, "error": error}), 409
        return jsonify({"success": True, "total": count}), 202
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 404
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/backups/restore/status', methods=['GET'])
def api_backups_restore_status():
    with _RESTORE_LOCK:
        return jsonify({"success": True, "state": copy.deepcopy(_RESTORE_STATE)})


@app.route('/api/devices/fs-restore', methods=['POST'])
def api_devices_fs_restore():
    try:
        data = request.get_json(force=True, silent=True) or {}
        macs = data.get("macs")
        if not isinstance(macs, list) or not macs:
            return jsonify({"success": False, "error": "macs must be a non-empty list"}), 400
        root = _backup_settings()["dir"]
        items = []
        missing = []
        for mac in macs:
            record = device_storage.get_device_by_mac(str(mac))
            if record is None:
                missing.append(str(mac))
                continue
            path, meta, _ = _latest_snapshot_for_mac(root, str(mac))
            if not path:
                missing.append(str(mac))
                continue
            items.append((record.to_dict(), path, meta))
        if missing:
            return jsonify({"success": False, "error": "No snapshot/device: " + ", ".join(missing)}), 404
        count, error = _start_restore(items)
        if error:
            return jsonify({"success": False, "error": error}), 409
        return jsonify({"success": True, "total": count}), 202
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/devices/fs-update', methods=['POST'])
def api_devices_fs_update():
    try:
        data = request.get_json(force=True, silent=True) or {}
        macs = data.get("macs")
        if not isinstance(macs, list) or not macs:
            return jsonify({"success": False, "error": "macs must be a non-empty list"}), 400
        count, error = _start_fs_update(macs)
        if error:
            return jsonify({"success": False, "error": error}), 409
        return jsonify({"success": True, "total": count}), 202
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/devices/fs-update/status', methods=['GET'])
def api_devices_fs_update_status():
    with _FS_UPDATE_LOCK:
        return jsonify({"success": True, "state": copy.deepcopy(_FS_UPDATE_STATE)})


# ============================================================
# Flask Routes — UDP настройки
# ============================================================
@app.route('/udp-settings', methods=['GET'])
def udp_settings_page():
    """Страница настроек UDP."""
    udp_cfg = config.get("udp_listener", {})
    tl_cfg = config.get("traffic_light", {})
    return render_template('udp_settings.html',
        udp_config=udp_cfg,
        traffic_light=tl_cfg,
        logging_config=config.get("logging", {}),
        listener_running=udp_listener.is_running,
        msg_count=udp_listener.msg_count
    )


@app.route('/api/udp/config', methods=['GET'])
def api_udp_config_get():
    """API: получить конфигурацию UDP."""
    return jsonify({
        "udp_listener": config.get("udp_listener", {}),
        "traffic_light": config.get("traffic_light", {}),
        "logging": config.get("logging", {})
    })


@app.route('/api/udp/config', methods=['POST'])
def api_udp_config_set():
    """API: обновить конфигурацию UDP."""
    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({"success": False, "error": "No data"}), 400

        # Обновляем UDP listener config
        if "udp_listener" in data:
            old_port = config["udp_listener"].get("receive_port")
            new_udp = data["udp_listener"]
            for k, v in new_udp.items():
                config["udp_listener"][k] = v
            save_config(config)

            # Перезапускаем слушатель если изменился порт
            new_port = config["udp_listener"].get("receive_port")
            if old_port != new_port:
                if config["udp_listener"].get("is_listening", True):
                    udp_listener.restart(new_port)
                else:
                    udp_listener.stop()

        # Обновляем traffic light config
        if "traffic_light" in data:
            for k, v in data["traffic_light"].items():
                config["traffic_light"][k] = v
            save_config(config)

        # Обновляем настройки файловых логов
        if "logging" in data:
            new_logging = data["logging"]
            for k, v in new_logging.items():
                config["logging"][k] = v
            if not config["logging"].get("directory"):
                config["logging"]["directory"] = "log"
            save_config(config)
            apply_logging_config(config["logging"])
            if config["logging"].get("enabled", True):
                print(f"File logging enabled: saved to '{config['logging'].get('directory', 'log')}'")

        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/udp/probe', methods=['POST'])
def api_udp_probe():
    """
    API: отправить broadcast-запрос (probe) устройствам.
    Отправляет keyword на transmit_port.
    Устройства, услышав keyword, отвечают своим JSON.
    """
    udp_cfg = config.get("udp_listener", {})
    keyword = udp_cfg.get("keyword", "Ave_Omnissiah")
    port = udp_cfg.get("transmit_port", 40001)

    # Отправляем keyword как probe-запрос
    # Устройства в udpResponseHandler() проверяют keyword и отвечают
    count = udp_listener.udp_tx_super_broadcast(keyword, port)
    print(f"Probe: keyword='{keyword}' port={port} sent={count}")
    return jsonify({"success": True, "sent_count": count})


# ============================================================
# Flask Routes — Настройки отображения (Display Format)
# ============================================================
@app.route('/api/display/format', methods=['GET'])
def api_display_format_get():
    """API: получить настройки отображения колонок."""
    fmt = load_display_format()
    return jsonify(fmt)


@app.route('/api/display/format', methods=['POST'])
def api_display_format_set():
    """API: обновить настройки отображения колонок."""
    try:
        data = request.get_json(force=True)
        if not data or "columns" not in data:
            return jsonify({"success": False, "error": "Missing columns"}), 400

        # Восстанавливаем label, если он отсутствует (из DEFAULT_DISPLAY_FORMAT)
        default_labels = {col['field']: col['label'] for col in DEFAULT_DISPLAY_FORMAT['columns']}
        for col in data.get('columns', []):
            if 'label' not in col or not col['label']:
                col['label'] = default_labels.get(col['field'], col['field'])

        if save_display_format(data):
            return jsonify({"success": True})
        return jsonify({"success": False, "error": "Save failed"}), 500
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================================
# Browse Folder (system dialog)
# ============================================================
def _browse_folder_dialog():
    """Open system folder picker dialog."""
    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        root.attributes('-topmost', True)
        folder = filedialog.askdirectory(title="Select Firmware Directory")
        root.destroy()
        if folder:
            return os.path.normpath(folder)
        return None
    except Exception as e:
        print(f"tkinter folder dialog failed: {e}")
        pass
    return None


@app.route('/browse-folder', methods=['POST'])
def browse_folder():
    """Open system folder picker dialog and return selected path."""
    try:
        folder = _browse_folder_dialog()
        if folder:
            return jsonify({"success": True, "path": folder})
        return jsonify({"success": False, "error": "No folder selected."})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================================
# Main
# ============================================================
if __name__ == '__main__':
    print(f"--- OTA Firmware Server ---")
    print(f"Admin Interface: http://{config['host']}:{config['port']}/")
    print(f"Manifest:        http://{config['host']}:{config['port']}{config['manifest_path']}")
    print(f"Firmware dirs:   {config['firmware_dirs']}")
    print(f"Firmware files:  {len(scan_firmware_files())}")
    print(f"UDP Listener:    {'Running' if udp_listener.is_running else 'Stopped'}")
    print(f"Devices tracked: {device_storage.get_total_count()}")

    # use_reloader=False: иначе Werkzeug порождает второй процесс, модульный код
    # выполняется дважды, оба процесса биндят UDP :40000. Пакеты достаются
    # родителю, а HTTP-процесс держит устаревший device_storage (см. «No devices found»).
    app.run(host=config['host'], port=config['port'], debug=True, use_reloader=False)
