# OTA Firmware Server + UDP Device Monitor (otasyncer-server)

## Назначение

Python-проект: **хостинг прошивок** и **сбор телеметрии** ESP-устройств по UDP.
Входит в экосистему `avr-fota` и является **главным и единственным** репозиторием
сервера (корень — этот каталог, `D:\github\avr-fota\otasyncer-server`). Отдельные
клоны вне `avr-fota` не использовать и не синхронизировать.

- Устройства шлют UDP-broadcast с JSON-телеметрией (`DeviceInfo`, ключ записи — `mac`);
- Веб-интерфейс показывает онлайн-устройства, события и файлы прошивок;
- Устройства (OTA-клиент `src/module_otaclient` в прошивке) периодически запрашивают
  `/manifest.json` и автоматически применяют новые файлы `{env}-FIRMWARE-*` и
  `{env}-FILESYS-*`.

## Запуск

```bash
python -m pip install -r requirements.txt
python app.py
```

- Admin UI: `http://<host>:8080/` (главная), `/devices`, `/udp-settings`
- Manifest для устройств: `/manifest.json?target=<BUILD_ENV>&ver=<версия>`
- UDP: receive `40000`, transmit `40001`, ключевое слово по умолчанию `Ave_Omnissiah`

Настройки — в `config.json` (UDP, логирование, `backup`, `device_username` /
`device_password`); данные об устройствах — в `devices_db.json`
(пересоздаются автоматически); колонки таблицы — в `display_format.json`.
`firmware_dirs` указывает на каталоги с `.bin`-файлами прошивок (второй каталог
обычно `D:\github\avr-fota\proj_fwbins` — сюда PlatformIO складывает собранные
`{env}-FIRMWARE-*` / `{env}-FILESYS-*`).

## Архитектура (app.py, один файл)

| Компонент | Что делает |
|---|---|
| `DeviceInfo` (dataclass) | Модель устройства из UDP-пакета; служебные поля `lastSeen`, `isOnline`, `allowFsUpdate`, `allowFwUpdate` |
| `DeviceStorage` | Персистентное хранилище устройств (`devices_db.json`), потокобезопасно (`threading.Lock`) |
| `EventLog` | Кольцевой буфер последних событий (in-memory) |
| `SseManager` | Рассылка событий браузерам по Server-Sent Events (`/api/events`) |
| `UdpListener` | Фоновый поток: приём UDP-broadcast, разбор JSON, обновление устройств; probe/super-broadcast по кнопке |
| `manifest()` | Формирует `/manifest.json` под конкретное устройство с учётом его политики обновлений |
| `_backup_worker` / `_backup_one_device` | Фоновый последовательный бэкап конфигов и Lua-скриптов выбранных устройств |
| Утилиты прошивок | `scan_firmware_files`, парсинг имён `{env}-{FIRMWARE|FILESYS}-{MAJOR}.{MINOR}.{DATE}_{TIME}.{BUILD}.bin`, удаление старых версий |

Периодическая задача (раз в минуту) помечает устройства офлайн
(`device_timeout_minutes`) и удаляет давно не появлявшиеся (`device_cleanup_hours`).

## Политика обновлений (важно)

Сервер **сам решает**, может ли устройство обновляться. В таблице `/devices` у
каждого устройства есть чекбоксы **«Обновление ФС»** и **«Обновление прошивки»**
(checked = разрешено). Состояние хранится индивидуально для каждого устройства в
полях `allowFsUpdate` / `allowFwUpdate`. По умолчанию оба запрещены (галочки не
стоят): новое устройство не обновляется, пока администратор явно не разрешит.

Семантика манифеста:
- тип запрещён → файлы этого типа в манифесте отсутствуют;
- тип разрешён → ровно **один самый свежий** файл этого типа;
- оба запрещены → `{"files": [], "has_files": false}`.

Идентификация устройства в запросе манифеста:
- приоритет — query-параметр `mac` (прошивка пока его не шлёт, но сервер готов);
- иначе сопоставление по IP источника TCP-соединения против записей `devices_db.json`
  (`DeviceStorage.find_device_for_update`);
- устройство не найдено → «запрещено всё» (поведение по умолчанию: новые
  устройства не обновляются, пока администратор не разрешит).

Ограничения (без правки прошивки):
- если IP устройства сменился (DHCP) и запись не совпала, применяется «запрещено всё»;
- запись с явным разрешением обновлений **не удаляется** фоновой очисткой
  (`cleanup_old` сохраняет устройства, у которых `allowFsUpdate`/`allowFwUpdate`
  хотя бы один `True`) — иначе явное разрешение терялось бы при возврате устройства.

Управление политикой: `POST /api/device/<mac>/update-policy`
с частичным JSON `{"allowFwUpdate": bool, "allowFsUpdate": bool}`.

## Бэкап конфигов и скриптов

В таблице `/devices` можно выделить одно или несколько устройств и нажать
**Backup Selected**. Сервер в фоне, строго последовательно заходит на каждое
устройство по HTTP и выгружает:

- JSON-конфиги (`config_*.json`, `secret.json`, `_version_fs.json`,
  `avrisp_cfg.json`, `avrisp.json`, `swd_cfg.json`, `/macros/resources.json`);
- Lua-скрипты `/macros/*.lua` (список берётся из `/macros/list`);
- `meta.json` с версиями устройства, списком файлов, SHA-256 и ошибками.

Папка: `backups/<devicename>_<serial>/` (например `esp32_D2A58`); повторный
успешный бэкап заменяет её содержимое. При ошибках существующая папка не
перезаписывается. HTML-страницы, JS/CSS, картинки и шрифты не выгружаются;
HTML-ответ 404 от ESP (с кодом 200) распознаётся и игнорируется.

- `POST /api/devices/backup` — тело `{"macs": ["..."]}`, запуск задания (202);
  повторный запуск во время работы → 409;
- `GET /api/devices/backup/status` — состояние и результаты;
- настройки — `backup` в `config.json` (`dir`, `timeout_s`,
  `inter_request_delay_ms`, `extra_config_files`);
- необязательные `device_username` / `device_password` — HTTP Basic для устройств.

## Ключевые HTTP-эндпоинты

- `GET /manifest.json` — манифест для OTA-клиента (см. выше)
- `GET /firmware/<filename>` — скачивание бинарника
- `POST /upload`, `POST /delete/<filename>` — загрузка/удаление файлов прошивок
- `GET/POST /api/devices`, `GET /api/device/<mac>`, `POST /api/device/<mac>/update-policy`
- `POST /api/devices/backup`, `GET /api/devices/backup/status` — бэкап конфигов/скриптов
- `POST /api/devices/clear` — очистить список устройств (сбрасывает и политики)
- `GET /api/events` (SSE), `GET /api/events/log`
- `POST /api/udp/probe` — broadcast-запрос к устройствам
- `GET/POST /api/display/format`, `GET/POST /api/udp/config`, `POST /config/dirs`

## Конвенции

- Код — Python + Flask (WSGI, один файл `app.py`), комментарии на русском.
- Веб-интерфейс: шаблоны Jinja2 в `templates/`, стили в `static/`.
- Конфиг/БД/формат — JSON-файлы рядом с `app.py`, секретов в репозиторий не класть.
- Изменения коммитить только в этот репозиторий (`D:\github\avr-fota\otasyncer-server`), а не в `avr-fota`.
- Проверка перед коммитом:
  ```bash
  python -m py_compile app.py
  ```
  Ручная проверка манифеста:
  `Invoke-WebRequest "http://127.0.0.1:8080/manifest.json?target=<env>"`.
