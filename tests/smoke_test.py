import json
import os
import shutil
import sys
import tempfile
import time
from urllib.parse import quote

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

TEST_DIR = tempfile.mkdtemp(prefix="otasyncer_test_")
CONFIG_PATH = os.path.join(TEST_DIR, "config.json")
with open(CONFIG_PATH, "w", encoding="utf-8") as f:
    json.dump({
        "host": "127.0.0.1", "port": 18080, "firmware_dirs": [],
        "device_username": "", "device_password": "", "device_http_port": 18081,
        "backup": {
            "dir": os.path.join(TEST_DIR, "backups"),
            "timeout_s": 2, "upload_timeout_s": 2, "inter_request_delay_ms": 0,
            "max_file_bytes": 1048576, "keep_manual": 10, "restore_verify": "size",
            "include_patterns": ["/config_*.json", "/secret.json", "/macros/*.lua",
                                 "/avrisp.json"],
            "exclude_patterns": ["/_version_fs.json", "/*_cfg.json"],
            "extra_config_files": [],
        },
        "fs_update": {"keep_snapshots": 5, "reconnect_timeout_s": 5,
                      "status_poll_s": 1, "restart_after_restore": False},
        "udp_listener": {"is_listening": False, "probe_devices_on_startup": False,
                         "receive_port": 40000, "transmit_port": 40001},
        "traffic_light": {}, "logging": {"enabled": False, "directory": "log"},
    }, f)

os.environ["OTASYNCER_CONFIG"] = CONFIG_PATH
os.environ["OTASYNCER_DEVICES_DB"] = os.path.join(TEST_DIR, "devices_db.json")
os.environ["OTASYNCER_TEST"] = "1"

from fake_device import FakeDevice  # noqa: E402
import app  # noqa: E402


MAC = "58:2A:BD:61:89:A8"


def wait_state(getter, timeout=30):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = getter()
        if not last.get("running"):
            return last
        time.sleep(0.1)
    raise AssertionError("job timeout: " + json.dumps(last, default=str)[:1000])


def main():
    device = FakeDevice(port=18081).start()
    backup_root = app._backup_settings()["dir"]
    shutil.rmtree(backup_root, ignore_errors=True)
    os.makedirs(backup_root, exist_ok=True)

    app.device_storage.clear_all()
    app.device_storage.update_device({
        "mac": MAC, "deviceName": "Electronica", "deviceSerial": "D003",
        "ip": "127.0.0.1", "target": "esp32_electronica7_rgb_macros",
    })
    client = app.app.test_client()

    # --- manual backup ---
    r = client.post("/api/devices/backup", json={"macs": [MAC]})
    assert r.status_code == 202, (r.status_code, r.data)
    state = wait_state(app._backup_state_snapshot, 30)
    assert state["results"], state
    result = state["results"][0]
    assert result["ok"], json.dumps(result, ensure_ascii=False)
    assert result["files"] == 3, result  # config_sys, secret, macros/a.lua
    sid = result["id"]
    assert sid.startswith("Electronica_D003__6189A8/"), sid
    snap_dir = result["snapshot"]
    assert os.path.isdir(snap_dir)
    with open(os.path.join(snap_dir, "meta.json"), encoding="utf-8") as f:
        meta = json.load(f)
    assert meta["schema"] == 2 and meta["kind"] == "manual"
    paths = {x["devicePath"] for x in meta["files"]}
    assert "/style.css" not in paths
    assert "/config_sys.json" in paths and "/secret.json" in paths

    # --- list / detail / old layout ignored ---
    old = os.path.join(backup_root, "Electronica_D003")
    os.makedirs(old, exist_ok=True)
    with open(os.path.join(old, "meta.json"), "w", encoding="utf-8") as f:
        json.dump({"schema": 1}, f)
    r = client.get("/api/backups")
    data = r.get_json()
    assert r.status_code == 200 and data["success"]
    assert len(data["backups"]) == 1, data
    assert data["backups"][0]["id"] == sid
    assert client.get("/api/backups/" + sid).status_code == 200
    f = client.get("/api/backups/" + sid + "/file?path=" + quote("/config_sys.json", safe=""))
    assert f.status_code == 200 and f.data == b'{"name":"esp32"}'
    f.close()

    # --- restore ---
    device.files["/config_sys.json"] = b"changed"
    r = client.post("/api/backups/" + sid + "/restore")
    assert r.status_code == 202, (r.status_code, r.data)
    state = wait_state(lambda: app._RESTORE_STATE, 30)
    assert state["results"] and state["results"][0]["ok"], state
    assert device.files["/config_sys.json"] == b'{"name":"esp32"}'

    # --- fs update job ---
    device.versionfs = "V1"
    device.test_code = 0
    device.fs_updated = False
    r = client.post("/api/devices/fs-update", json={"macs": [MAC]})
    assert r.status_code == 202, (r.status_code, r.data)
    state = wait_state(lambda: app._FS_UPDATE_STATE, 30)
    assert state["results"], state
    job = state["results"][0]
    assert job["ok"], job
    assert job["oldVersionFs"] == "V1" and job["newVersionFs"] == "V2"
    assert device.fs_updated
    assert job["snapshot"].endswith("_fs_update")
    dev = app.device_storage.get_device_by_mac(MAC)
    assert dev.allowFsUpdate is False and dev.allowFwUpdate is False

    # --- delete ---
    r = client.delete("/api/backups/" + sid)
    assert r.status_code == 200, (r.status_code, r.data)
    data = client.get("/api/backups").get_json()
    assert all(x["id"] != sid for x in data["backups"])

    # --- cleanup old layout and job snapshots ---
    shutil.rmtree(backup_root, ignore_errors=True)
    device.stop()
    shutil.rmtree(TEST_DIR, ignore_errors=True)
    print("SMOKE_OK")


if __name__ == "__main__":
    main()
