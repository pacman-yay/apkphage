import os
import queue
import subprocess
import sys
import threading
import time

ADB = "adb"  # assumes ADB is reachable, e.g. connected to the emulator container's exposed port

SANDBOX_NAME = "apkphage-sandbox"
# Software-emulated Android (no KVM) can take several minutes to boot.
BOOT_TIMEOUT = 900  # seconds
ADB_CONNECT_RETRIES = 180
INSTALL_TIMEOUT = 1200  # seconds - generous for a large APK over software emulation
PM_WAIT_TIMEOUT = 180

# Rotating loader characters - visible "motion" so long phases never look frozen.
_SPIN = "|/-\\"
_HEARTBEAT_EVERY = 15  # seconds between heartbeat lines in streamed phases

# Lines in frida's output that prove the session NEVER attached (vs a hook
# that attached but hit a benign in-script error like a missing class).
_ATTACH_FAILURE_MARKERS = [
    "Failed to spawn",
    "Failed to attach",
    "unexpectedly timed out while waiting",
    "Unable to find process with pid",
    "Unable to find process with name",
    "not found",
    "Invalid target",
    "Unable to connect to remote frida-server",
]


def _adb(*args, **kwargs):
    return subprocess.run([ADB] + list(args), capture_output=True, text=True, **kwargs)


def _print_sandbox_logs():
    """Dump the sandbox container logs - shows binder/ashmem/emulator errors.
    Only works when run on the host with the docker CLI; degrades to a hint
    when running inside the container."""
    try:
        logs = subprocess.run(
            ["docker", "logs", "--tail", "80", SANDBOX_NAME],
            capture_output=True,
            text=True,
        )
        tail = (logs.stdout + logs.stderr)[-4000:]
        print("[+] ---- apkphage-sandbox container logs (tail) ----", file=sys.stderr)
        print(tail, file=sys.stderr)
        print("[+] ------------------------------------------------", file=sys.stderr)
    except Exception:
        print(
            f"[-] Inspect the sandbox from the host:  docker logs --tail 80 {SANDBOX_NAME}",
            file=sys.stderr,
        )


def _spinner_line(label: str, elapsed: int, status: str = "") -> str:
    """Return an in-place \r loader line (single terminal line, self-overwriting)."""
    char = _SPIN[elapsed % len(_SPIN)]
    status_txt = f" - {status}" if status else ""
    return f"\r[*] {label}... ({elapsed}s) {char}{status_txt}    "


def _poll_beat(label, deadline, interval: float = 1.0):
    """Generator-friendly per-second \r ticker proving a poll loop is alive."""
    start = time.time()
    last = 0.0
    while True:
        now = time.time()
        if now - last >= interval:
            elapsed = int(now - start)
            yield f"\r[*] {label}... ({elapsed}s) {_SPIN[elapsed % 4]}\r"
            last = now
            if now >= deadline:
                return
        time.sleep(0.1)


def _wait_booted(timeout: float) -> bool:
    """Poll sys.boot_completed until it reads 1 or the timeout elapses."""
    deadline = time.time() + timeout
    start = time.time()
    last_beat = 0.0
    while time.time() < deadline:
        res = _adb("shell", "getprop", "sys.boot_completed", timeout=15)
        if res.returncode == 0 and res.stdout.strip() == "1":
            print("\r", end="")
            return True
        now = time.time()
        if now - last_beat >= 1:
            elapsed = int(now - start)
            print(
                "\r"
                + f"[*] waiting for Android to finish booting... ({elapsed}s) {_SPIN[elapsed % 4]}   ",
                end="",
                flush=True,
            )
            last_beat = now
        time.sleep(2)
    print("\r", end="")
    return False


def _dex2oat_running() -> bool:
    """True when the guest is AOT-compiling (the normal post-install slow phase)."""
    res = _adb("shell", "ps -A | grep dex2oat", timeout=5)
    return res.returncode == 0 and "dex2oat" in res.stdout


def _run_with_liveness(
    args, every: float = _HEARTBEAT_EVERY, hint: str = "", status_fn=None, timeout: float = None
) -> subprocess.CompletedProcess:
    """Run a command, streaming its stdout live, with heartbeat ticks while idle.

    Prevents the classic 'frozen-looking' long phase: the operator always sees
    either real output or a rotating heartbeat that proves the pipeline is
    still alive and states what is happening. `status_fn` (optional) can return
    a dynamic, honest description of what the guest is doing right now.

    Uses a reader thread so it is portable (works inside the Linux analyzer
    container and on the Windows host alike)."""
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    queue_ = queue.Queue()

    def _reader():
        for line in iter(proc.stdout.readline, ""):
            queue_.put(line)

    threading.Thread(target=_reader, daemon=True).start()

    start = time.time()
    last_beat = start
    out_lines = []
    while proc.poll() is None:
        try:
            line = queue_.get(timeout=1)
            out_lines.append(line)
            print(line, end="", flush=True)
            last_beat = time.time()  # real output is a heartbeat too
        except queue.Empty:
            if time.time() - last_beat >= every:
                elapsed = int(time.time() - start)
                char = _SPIN[elapsed % len(_SPIN)]
                status = ""
                if status_fn:
                    try:
                        status = status_fn()
                    except Exception:
                        # The status probe is purely cosmetic - it must never
                        # be able to kill a running command. A probe that times
                        # out (adb briefly unresponsive under software emulation)
                        # degrades to "checking guest" instead of failing.
                        status = "checking guest..."
                h = f" | {hint}" if hint else ""
                s = f" | {status}" if status else ""
                # In-place rewrite (no newline) so heartbeats never spam the
                # scrollback. The CLI's master progress panel already ticks
                # the phase's elapsed time, so this is only reassurance that
                # the command is alive; it collapses to its last frame when
                # captured by the panel's stream normalizer.
                sys.stdout.write(f"\r[*] still working... ({elapsed}s) {char}{h}{s}")
                sys.stdout.flush()
                last_beat = time.time()
            if timeout and time.time() - start > timeout:
                proc.terminate()
                print(f"[-] command timed out after {int(timeout)}s; killed.", file=sys.stderr)
                break
    # Clear the leftover rotating heartbeat line before trailing output.
    sys.stdout.write("\r" + " " * 120 + "\r")
    sys.stdout.flush()
    # Drain any trailing output
    while not queue_.empty():
        line = queue_.get_nowait()
        out_lines.append(line)
        print(line, end="", flush=True)
    return subprocess.CompletedProcess(proc.args, proc.returncode, "".join(out_lines), "")


def wait_for_device():
    host_ip = os.environ.get("HOST_IP", SANDBOX_NAME)
    print(f"[+] Waiting for sandbox ADB at {host_ip}:5555...", flush=True)

    # Retry loop because adbd might take a few seconds to bind
    connected = False
    start = time.time()
    last_beat = 0.0
    for attempt in range(ADB_CONNECT_RETRIES):
        res = _adb("connect", f"{host_ip}:5555", timeout=10)
        if "connected to" in res.stdout.lower() or "already connected" in res.stdout.lower():
            connected = True
            break
        now = time.time()
        if now - last_beat >= 1:
            elapsed = int(now - start)
            print(
                "\r"
                + f"[*] retrying adb connect... (attempt {attempt + 1}, {elapsed}s) {_SPIN[elapsed % 4]}   ",
                end="",
                flush=True,
            )
            last_beat = now
        time.sleep(1)
    print("\r", end="")

    if not connected:
        print("[-] ADB never connected to the sandbox.", file=sys.stderr)
        print("    Inspect the sandbox (docker logs) for KVM/emulator errors.", file=sys.stderr)
        _print_sandbox_logs()
        sys.exit(1)

    if not _wait_booted(BOOT_TIMEOUT):
        print("[-] Sandbox did not finish booting within timeout.", file=sys.stderr)
        print(
            "    Check KVM/binder modules. A VM without nested virt may never boot it.",
            file=sys.stderr,
        )
        _print_sandbox_logs()
        sys.exit(1)

    # Setup Frida on the sandbox instance
    print("[+] Injecting Frida Server into Sandbox...", flush=True)
    _adb("root")  # Ensure root
    _adb("connect", f"{host_ip}:5555")  # Reconnect if root restarted adb
    if not _wait_booted(30):
        print("[-] Device offline after adb root. Aborting.", file=sys.stderr)
        _print_sandbox_logs()
        sys.exit(1)

    print("[+] Pushing frida-server to the device...", flush=True)
    _run_with_liveness(
        [ADB, "push", "/opt/frida-server", "/data/local/tmp/frida-server"],
        hint="large binary; software emulation makes the copy slow",
        timeout=600,
    )
    subprocess.run(
        [ADB, "shell", "chmod", "755", "/data/local/tmp/frida-server"],
        check=True,
        capture_output=True,
    )

    # Start frida-server in the background
    subprocess.run(
        [ADB, "shell", "nohup /data/local/tmp/frida-server >/dev/null 2>&1 &"], check=False
    )
    time.sleep(2)  # Give it time to bind to port

    # Configure Global HTTP Proxy if mitmproxy is enabled
    proxy_ip = os.environ.get("MITM_PROXY_IP")
    if proxy_ip:
        print(f"[+] Setting Global HTTP Proxy to {proxy_ip}:8080...", flush=True)
        subprocess.run(
            [ADB, "shell", "settings", "put", "global", "http_proxy", f"{proxy_ip}:8080"],
            check=False,
        )


def _wait_package_manager(timeout: float = PM_WAIT_TIMEOUT) -> bool:
    """Wait until the package manager (system_server) is actually responsive.

    sys.boot_completed=1 can still leave the package service settling on slow
    software-emulated devices; an install right then often dies with a broken
    pipe. This polls `pm path android` until it answers cleanly."""
    deadline = time.time() + timeout
    start = time.time()
    last_beat = 0.0
    while time.time() < deadline:
        res = _adb("shell", "pm", "path", "android", timeout=15)
        if res.returncode == 0 and res.stdout.strip():
            print("\r", end="")
            return True
        now = time.time()
        if now - last_beat >= 1:
            elapsed = int(now - start)
            print(
                "\r" + f"[*] waiting for package manager... ({elapsed}s) {_SPIN[elapsed % 4]}   ",
                end="",
                flush=True,
            )
            last_beat = now
        time.sleep(3)
    print("\r", end="")
    return False


def install_apk(apk_path: str):
    if not _wait_package_manager():
        raise RuntimeError("Package manager never became responsive after boot")

    last_err = None
    # Software emulation + big APKs can crash system_server (the package
    # service host) mid-install. Each retry first waits for the service to
    # come back - a fixed sleep is too short for the 30-60s restart window.
    for attempt in range(1, 4):
        print(f"[+] Installing APK (attempt {attempt}/3)...", flush=True)
        res = _run_with_liveness(
            [ADB, "install", "-r", apk_path],
            timeout=INSTALL_TIMEOUT,
            hint="large APK + software emulation makes install slow",
            status_fn=lambda: (
                "dex2oat/AOT compiling in guest - progress confirmed"
                if _dex2oat_running()
                else "guest idle (still transferring or stuck?)"
            ),
        )
        if res.returncode == 0:
            print(f"[+] APK installed (attempt {attempt})", flush=True)
            return
        last_err = (res.returncode, res.stderr)
        print(f"[-] install attempt {attempt}/3 failed ({res.returncode}); retrying...", flush=True)
        # 'Can't find service: package' / 'Broken pipe' => system_server is
        # restarting. Reboot-wait (graceful, up to 180s) before the retry.
        if not _wait_package_manager():
            print("[-] package manager did not come back after failure; aborting.", file=sys.stderr)
            break
    raise (
        subprocess.CalledProcessError(*last_err) if last_err else RuntimeError("APK install failed")
    )


def get_package_name(apktool_manifest_findings: dict) -> str:
    return apktool_manifest_findings["package"]


def launch_app(package_name: str):
    print(f"[+] Launching {package_name}...", flush=True)
    _run_with_liveness(
        [ADB, "shell", "monkey", "-p", package_name, "-c", "android.intent.category.LAUNCHER", "1"],
        hint="starting the target app",
        timeout=300,
    )


def _get_pid(package_name: str, timeout: float = 120) -> str | None:
    """Return the guest PID for a package once its process is up."""
    start = time.time()
    last_beat = 0.0
    while time.time() - start < timeout:
        res = _adb("shell", f"pidof {package_name}", timeout=10)
        pid = res.stdout.strip()
        if pid:
            return pid.split()[-1]  # newest process if multiple
        now = time.time()
        if now - last_beat >= 2:
            elapsed = int(now - start)
            print(
                "\r"
                + f"[*] waiting for {package_name} process... ({elapsed}s) {_SPIN[elapsed % 4]}   ",
                end="",
                flush=True,
            )
            last_beat = now
        time.sleep(1)
    print("\r", end="")
    return None


def _frida_attach_failed(line: str) -> bool:
    """True if a frida output line proves the session never attached."""
    return any(marker.lower() in line.lower() for marker in _ATTACH_FAILURE_MARKERS)


def run_frida_hooks(
    package_name: str, script_path: str, duration_seconds: int = 60, max_attempts: int = 3
) -> dict:
    """Attach frida by PID (spawn mode is unreliable on software emulation),
    verifying each attach, retrying on failure, and grading the evidence.

    Returns a dict fit for pipeline_status / report evidence instead of a bare
    log: the caller can show "attached: true" or "attach failed after N tries"
    honestly instead of implying a session happened."""
    all_lines: list[str] = []
    attached = False
    quit_marker = False

    for attempt in range(1, max_attempts + 1):
        print(f"\n[+] Frida attach attempt {attempt}/{max_attempts}...", flush=True)
        launch_app(package_name)
        pid = _get_pid(package_name, timeout=60)
        if pid:
            attach_target, attach_flag = pid, "-p"
            print(f"[+] {package_name} up (pid {pid}) - attaching Frida...", flush=True)
        else:
            print("[-] app never spawned a process; trying attach by name", flush=True)
            attach_target, attach_flag = package_name, "-n"

        proc = subprocess.Popen(
            ["frida", "-U", attach_flag, attach_target, "-l", script_path],
            stdin=subprocess.DEVNULL,  # never block on a REPL prompt
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        q = queue.Queue()

        def _reader(p=proc, q_ref=q):
            for line in iter(p.stdout.readline, ""):
                q_ref.put(line)

        threading.Thread(target=_reader, daemon=True).start()

        start = time.time()
        attempt_lines = []
        attempt_ok = True
        last_beat = start
        print(f"[+] Attaching frida for {duration_seconds}s...", flush=True)

        while time.time() - start < duration_seconds:
            try:
                line = q.get(timeout=1)
                attempt_lines.append(line)
                print(line, end="", flush=True)
                if _frida_attach_failed(line):
                    # Real frida errors land within seconds; treat as instant fail.
                    attempt_ok = False
                    quit_marker = True
                    break
                last_beat = time.time()
            except queue.Empty:
                if time.time() - last_beat >= 90:
                    # No output for a while. If the process is still alive, the
                    # session is holding; keep going (silence is normal for
                    # hooks that log nothing). If it exited, we lost it.
                    if proc.poll() is not None:
                        attempt_ok = False
                        break
                    last_beat = time.time()
        # Drain anything frida printed in the final moments, then stop it.
        while not q.empty():
            line = q.get_nowait()
            attempt_lines.append(line)
            print(line, end="", flush=True)
        if attempt_ok and proc.poll() is None:
            # Session survived the full window and never said it failed.
            attached = True
        else:
            # If break happened mid-drain, terminate cleanly before retrying.
            print("[-] attach did not confirm; retrying...", flush=True)
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        all_lines.extend(attempt_lines)
        if attached:
            break

    result = {
        "attached": attached,
        "attempts": attempt,
        "quit_marker": quit_marker,
        "output_lines": len(all_lines),
        "log": all_lines,
    }
    return result
