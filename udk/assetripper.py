"""Drive AssetRipper's headless web server: load a game folder, export it as a Unity project."""
import os
import socket
import subprocess
import time
import urllib.parse
import urllib.request


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def post(port, route, timeout, **form):
    body = urllib.parse.urlencode(form).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}{route}", data=body, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status


def export(binary, game_data_dir, out_dir, timeout=4 * 3600):
    """AssetRipper writes <out_dir>/ExportedProject (Assets/, ProjectSettings/) and AuxiliaryFiles."""
    os.makedirs(out_dir, exist_ok=True)
    port = free_port()
    logf = os.path.join(out_dir, "assetripper.log")
    proc = subprocess.Popen([binary, "--headless", "--port", str(port), "--log-path", logf],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(120):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=2)
                break
            except OSError:
                time.sleep(1)
        else:
            raise RuntimeError(f"AssetRipper did not start; see {logf}")
        t = time.time()
        post(port, "/LoadFolder", timeout, Path=game_data_dir)
        print(f"[assetripper] loaded in {time.time() - t:.0f}s", flush=True)
        t = time.time()
        post(port, "/Export/UnityProject", timeout, Path=out_dir)
        print(f"[assetripper] exported in {time.time() - t:.0f}s", flush=True)
    finally:
        proc.terminate()
        try:
            proc.wait(30)
        except subprocess.TimeoutExpired:
            proc.kill()
