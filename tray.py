#!/usr/bin/env python3
"""
Запуск OTA Firmware Server в системном трее (Windows).

Импортирует app.py (который при импорте уже поднимает UDP-слушатель и фоновые
потоки), запускает Flask-сервер в фоновом потоке и показывает иконку в трее.

Запуск без консоли:  pythonw tray.py
Запуск с консолью:   python tray.py

Любая ошибка запуска пишется в tray_error.log и показывается в message box,
чтобы не было «молчаливого» закрытия окна.
"""

import os
import sys
import traceback

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ICON_PATH = os.path.join(BASE_DIR, "icon.png")
ERROR_LOG = os.path.join(BASE_DIR, "tray_error.log")
HOST_BROWSER = "127.0.0.1"


def _fail(message: str):
    """Записать ошибку в tray_error.log, показать message box и выйти."""
    try:
        with open(ERROR_LOG, "a", encoding="utf-8") as f:
            f.write("=" * 60 + "\n")
            f.write(message + "\n")
    except Exception:
        pass
    try:
        import tkinter as tk
        from tkinter import messagebox
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("OTA Firmware Server", message)
        root.destroy()
    except Exception:
        pass
    sys.exit(1)


def main():
    import threading
    import webbrowser

    import pystray
    from PIL import Image, ImageDraw
    from werkzeug.serving import make_server

    import app as server

    port = server.config.get("port", 8080)

    def load_icon():
        """Загрузить icon.png; при отсутствии — сгенерировать фолбэк в памяти."""
        if os.path.exists(ICON_PATH):
            try:
                return Image.open(ICON_PATH)
            except Exception as e:
                print(f"[tray] icon load error: {e}, fallback to generated")
        img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        draw.rounded_rectangle((2, 2, 61, 61), radius=12, fill=(31, 119, 180, 255))
        draw.text((32, 32), "O", fill="white", anchor="mm")
        return img

    def open_ui(icon, item):
        webbrowser.open(f"http://{HOST_BROWSER}:{port}/")

    # Flask-сервер в фоновом потоке. threaded=True обязателен: /api/events (SSE)
    # держит долгоживущие соединения, иначе один клиент заблокирует весь сервер.
    try:
        httpd = make_server(server.config.get("host", "0.0.0.0"), port,
                            server.app, threaded=True)
    except OSError as e:
        print(f"[tray] failed to start HTTP server on port {port}: {e}")
        _fail(f"Не удалось запустить HTTP-сервер на порту {port}:\n{e}\n\n"
              "Возможно, сервер уже запущен (проверьте процессы Python).")

    http_thread = threading.Thread(target=httpd.serve_forever,
                                   daemon=True, name="http-server")
    http_thread.start()

    def on_quit(icon, item):
        httpd.shutdown()
        server.udp_listener.stop()
        icon.stop()

    menu = pystray.Menu(
        pystray.MenuItem("Открыть веб-интерфейс", open_ui),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Выход", on_quit),
    )

    icon = pystray.Icon("otasyncer", load_icon(), "OTA Firmware Server", menu=menu)

    print(f"[tray] HTTP server running on http://{HOST_BROWSER}:{port}/")
    icon.run()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        _fail("Ошибка при запуске трея:\n\n" + traceback.format_exc())
