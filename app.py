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
import threading
import socket
import struct
import time
import queue
import copy
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional

from flask import Flask, request, redirect, url_for, send_file, jsonify, render_template, Response
from werkzeug.utils import secure_filename

# ============================================================
# Константы
# ============================================================
CONFIG_FILE = 'config.json'
DEVICES_DB_FILE = 'devices_db.json'
DISPLAY_FORMAT_FILE = 'display_format.json'

# Максимальное количество записей в логе событий
MAX_EVENT_LOG_SIZE = 200

DEFAULT_CONFIG = {
    "host": "0.0.0.0",
    "port": 8080,
    "firmware_dirs": ["./firmware"],
    "manifest_path": "/manifest.json",
    "udp_listener": {
        "is_listening": True,
        "receive_port": 40000,
        "transmit_port": 40001,
        "keyword": "Ave_Omnissiah",
        "device_timeout_minutes": 10,
        "device_cleanup_hours": 24
    },
    "traffic_light": {
        "is_minutes_mode": True,
        "green_time": 1,
        "yellow_time": 2,
        "red_time": 3
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
# Flask приложение
# ============================================================
app = Flask(__name__)

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
                    if last < cutoff:
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
# Загрузка/сохранение конфигурации
# ============================================================
def load_config():
    """Загрузить конфигурацию из файла."""
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                cfg = json.load(f)
            merged = DEFAULT_CONFIG.copy()
            merged.update(cfg)
            # Убедимся, что вложенные секции есть
            for section in ['udp_listener', 'traffic_light']:
                if section not in merged:
                    merged[section] = DEFAULT_CONFIG[section].copy()
                else:
                    dflt = DEFAULT_CONFIG[section]
                    for k, v in dflt.items():
                        if k not in merged[section]:
                            merged[section][k] = v
            # Ensure firmware_dirs is a list
            if not isinstance(merged["firmware_dirs"], list):
                merged["firmware_dirs"] = [merged["firmware_dirs"]]
            return merged
        except Exception as e:
            print(f"Error loading config: {e}")
            return DEFAULT_CONFIG.copy()
    return DEFAULT_CONFIG.copy()


def save_config(cfg):
    """Сохранить конфигурацию в файл."""
    to_save = {
        "host": cfg.get("host", DEFAULT_CONFIG["host"]),
        "port": cfg.get("port", DEFAULT_CONFIG["port"]),
        "firmware_dirs": cfg.get("firmware_dirs", DEFAULT_CONFIG["firmware_dirs"]),
        "manifest_path": cfg.get("manifest_path", DEFAULT_CONFIG["manifest_path"]),
        "udp_listener": cfg.get("udp_listener", DEFAULT_CONFIG["udp_listener"]),
        "traffic_light": cfg.get("traffic_light", DEFAULT_CONFIG["traffic_light"])
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

        print(f"Super broadcast: sent {sent_count} packets on port {port}")
        return sent_count


# ============================================================
# Инициализация
# ============================================================
config = load_config()
display_format = load_display_format()
device_storage = DeviceStorage(DEVICES_DB_FILE)
event_log = EventLog()
sse_manager = SseManager()
udp_listener = UdpListener(device_storage, sse_mgr=sse_manager, event_log=event_log)

# Запуск UDP-слушателя
udp_cfg = config.get("udp_listener", {})
if udp_cfg.get("is_listening", True):
    udp_listener.start(udp_cfg.get("receive_port", 40000))

# Ensure all firmware dirs exist
for d in config["firmware_dirs"]:
    os.makedirs(d, exist_ok=True)


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
    """Determine file type from filename: 'firmware' or 'filesystem'."""
    if "_fs-" in filename:
        return "filesystem"
    return "firmware"


def scan_firmware_files():
    """Scan all firmware directories and return list of file entries."""
    entries = []
    for dir_path in config["firmware_dirs"]:
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
    for dir_path in config["firmware_dirs"]:
        candidate = os.path.join(dir_path, safe_name)
        if os.path.exists(candidate):
            return candidate
    return None


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

        target_dir = config["firmware_dirs"][0] if config["firmware_dirs"] else "./firmware"
        os.makedirs(target_dir, exist_ok=True)
        filepath = os.path.join(target_dir, filename)
        try:
            file.save(filepath)
            md5 = calculate_md5(filepath)
            return redirect(url_for('index',
                message=f"Success! Uploaded '{filename}' to {target_dir} (MD5: {md5})"))
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
    """Generate manifest.json for OTA client devices."""
    entries = scan_firmware_files()
    clean = []
    for e in entries:
        clean.append({
            "name": e["name"],
            "type": e["type"],
            "size": e["size"],
            "md5": e["md5"]
        })
    return jsonify({"files": clean})


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
        "udp_listener": config.get("udp_listener", {}),
        "traffic_light": config.get("traffic_light", {})
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

        for d in new_dirs:
            os.makedirs(d, exist_ok=True)

        config["firmware_dirs"] = new_dirs
        save_config(config)

        return jsonify({"success": True, "firmware_dirs": config["firmware_dirs"]})
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
        listener_running=udp_listener.is_running,
        msg_count=udp_listener.msg_count
    )


@app.route('/api/udp/config', methods=['GET'])
def api_udp_config_get():
    """API: получить конфигурацию UDP."""
    return jsonify({
        "udp_listener": config.get("udp_listener", {}),
        "traffic_light": config.get("traffic_light", {})
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

    app.run(host=config['host'], port=config['port'], debug=True)
