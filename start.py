from __future__ import annotations

import os
import threading
import webbrowser

import uvicorn


def main() -> None:
    port = int(os.getenv("STORAGECHECK_PORT", "8765"))
    url = f"http://127.0.0.1:{port}"
    threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    uvicorn.run("storagecheck.main:app", host="127.0.0.1", port=port, reload=False)


if __name__ == "__main__":
    main()
