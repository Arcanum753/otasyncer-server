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

## Версионные бэкапы (snapshots)

Нужна прошивка с `core_fs` (`/fs/info`, `api == 1`). Старые прошивки без него и
старая раскладка `backups/<device>/` **не поддерживаются** (прототип, обратной
совместимости нет).

В таблице `/devices` выделить устройства и нажать **Backup Selected**. Сервер
последовательно читает `/system/version`, `/fs/info`, один `/fs/list` и качает
только файлы из `backup.include_patterns` через `/fs/download`:

- `config_*.json`, `secret.json`, `macros/*.lua`, `avrisp.json`;
- исключаются `_version_fs.json`, `*_cfg.json`, HTML/JS/CSS/шрифты/картинки;
- SHA-256 считается на сервере; на ESP нет архивации/хеширования.

Каждый бэкап — новая папка:
`backups/<devicename>_<serial>__<mac6>/<YYYYMMDD_HHMMSS>_<kind>/` (+ `meta.json`,
`schema=2`, `kind=manual|fs_update`). Файлы хранятся как есть, без ZIP.
Retention: `backup.keep_manual`, `fs_update.keep_snapshots`.

Управление: страница `/backups` (+ API):
`GET /api/backups`, `GET /api/backups/<id>`, `GET /api/backups/<id>/file?path=`,
`DELETE /api/backups/<id>`, `POST /api/backups/delete`, `POST /api/backups/<id>/restore`,
`GET /api/backups/restore/status`.

FS-обновление с сохранением настроек: `POST /api/devices/fs-update`
(`{"macs":[...]}`) — snapshot → `allowFsUpdate=true/allowFwUpdate=false` →
`/otaclient/test` (только `-FILESYS-`) + `/otaclient/update` → ожидание нового
`versionfs` → `/fs/upload` restore → restart → возврат политик.
Статус: `GET /api/devices/fs-update/status`; shortcut restore —
`POST /api/devices/fs-restore`.

Нагрузка: backup = 3 + N запросов, restore (size-verify) = 1 + N + 1; без
пофайловых re-download (`backup.restore_verify=size`), `hash` — опционально.

Настройки: `device_http_port`, `backup` (`dir`, `timeout_s`, `upload_timeout_s`,
`inter_request_delay_ms`, `max_file_bytes`, `keep_manual`, `restore_verify`,
`include_patterns`, `exclude_patterns`, `extra_config_files`), `fs_update`
(`keep_snapshots`, `reconnect_timeout_s`, `status_poll_s`, `restart_after_restore`).
`device_username`/`device_password` — HTTP Basic.

Тесты: `tests/smoke_test.py` / `python -m pytest tests -q` (fake-device);
реальное устройство — только `192.168.88.134` / MAC `58:2A:BD:61:89:A8`.

## Ключевые HTTP-эндпоинты

- `GET /manifest.json` — манифест для OTA-клиента (см. выше)
- `GET /firmware/<filename>` — скачивание бинарника
- `POST /upload`, `POST /delete/<filename>` — загрузка/удаление файлов прошивок
- `GET/POST /api/devices`, `GET /api/device/<mac>`, `POST /api/device/<mac>/update-policy`
- `POST /api/devices/backup`, `GET /api/devices/backup/status` — versioned-снимки
- `GET /api/backups` (+ `/<id>`, `/<id>/file`, `/<id>/restore`, delete), `/backups`
- `POST /api/devices/fs-update`, `GET /api/devices/fs-update/status`, `POST /api/devices/fs-restore`
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
