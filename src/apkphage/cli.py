import glob
import json
import os
import shutil
import subprocess
import sys
import threading


def bootstrap():
    package_dir = os.path.dirname(os.path.abspath(__file__))
    venv_dir = os.path.join(package_dir, ".venv")

    if sys.platform == "win32":
        python_exe = os.path.join(venv_dir, "Scripts", "python.exe")
    else:
        python_exe = os.path.join(venv_dir, "bin", "python")

    if not os.path.exists(python_exe):
        print("[*] Virtual environment python missing. Recreating .venv...")
        if os.path.exists(venv_dir):
            shutil.rmtree(venv_dir, ignore_errors=True)
        subprocess.run([sys.executable, "-m", "venv", ".venv"], check=True)

    if sys.prefix == sys.base_prefix:
        sys.exit(subprocess.run([python_exe] + sys.argv).returncode)

    try:
        import questionary  # noqa: F401
        import rich  # noqa: F401
    except ImportError:
        print("[*] Installing missing dependencies in virtual environment...")
        if os.path.exists("host_requirements.txt"):
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "-r", "host_requirements.txt"], check=True
            )
        else:
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "install",
                    "google-genai==2.19.0",
                    "groq>=0.9.0",
                    "rich>=13.0.0",
                    "questionary>=2.0.0",
                ],
                check=True,
            )
        sys.exit(subprocess.run([sys.executable] + sys.argv).returncode)


# Bootstrap the virtual environment and re-launch if necessary
bootstrap()

if sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")

import questionary
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.spinner import SPINNERS
from rich.table import Table

SPINNERS["cyber_loader"] = {
    "interval": 100,
    "frames": [
        "█ │ │ │ │ │",
        "│ █ │ │ │ │",
        "│ │ █ │ │ │",
        "│ │ │ █ │ │",
        "│ │ │ │ █ │",
        "│ │ │ │ │ █",
        "│ │ │ │ █ │",
        "│ │ │ █ │ │",
        "│ │ █ │ │ │",
        "│ █ │ │ │ │",
    ],
}

console = Console()
package_dir = os.path.dirname(os.path.abspath(__file__))
cwd = os.getcwd()
SAMPLES_DIR = os.path.join(cwd, "samples")
WORK_DIR = os.path.join(cwd, "work")


def print_banner():
    import platform
    import subprocess

    # --- Status bar: samples, reports, AI key, Docker ---
    apks = glob.glob(os.path.join(SAMPLES_DIR, "*.apk"))
    reports = glob.glob(os.path.join(WORK_DIR, "*", "report.json"))
    stages = glob.glob(os.path.join(WORK_DIR, "*", "llm_stage.json"))
    sample_count = len(apks)
    report_count = len(reports)
    pending_count = len(stages) - report_count

    provider = os.environ.get("LLM_PROVIDER", "groq")
    groq_key = bool(os.environ.get("GROQ_API_KEY"))
    if provider == "groq" or groq_key:
        ai_status = "[green]Groq configured[/green]"
    elif groq_key:
        ai_status = "[yellow]Groq key missing[/yellow]"
    else:
        ai_status = "[yellow]No AI key[/yellow]"

    try:
        r = subprocess.run(["docker", "info"], capture_output=True, timeout=3)
        docker_ok = r.returncode == 0
    except Exception:
        docker_ok = False
    docker_status = "[green]Docker online[/green]" if docker_ok else "[red]Docker offline[/red]"

    pending_str = f"  [yellow]({pending_count} pending AI)[/yellow]" if pending_count > 0 else ""

    banner = f"""[bold blue]APKPhage v3.0.0[/bold blue]
[bold white]Automated Android Malware Analysis Pipeline[/bold white]

  [cyan]Samples:[/cyan] {sample_count} APK  [dim]|[/dim]  [cyan]Reports:[/cyan] {report_count}{pending_str}  [dim]|[/dim]  [cyan]AI:[/cyan] {ai_status}  [dim]|[/dim]  [cyan]Docker:[/cyan] {docker_status}

  [dim white]{platform.system()}/{platform.machine()}[/dim white]  [dim]|[/dim]  [dim white]Stack: Docker, Apktool, Jadx, Frida, Android Emulator (software)[/dim white]
  [bold blue]Static: container (--network none)  |  Dynamic: Android Emulator (software) + Frida  |  AI: host-side Groq[/bold blue]"""

    console.print(Panel(banner, border_style="blue", padding=(1, 2), expand=False))


ENV_FILE = os.path.join(package_dir, ".env")


def load_env():
    if os.path.exists(ENV_FILE):
        with open(ENV_FILE) as f:
            for line in f:
                line = line.strip()
                if "=" in line:
                    k, v = line.split("=", 1)
                    os.environ[k] = v


load_env()


def get_or_prompt_api_key():
    provider = os.environ.get("LLM_PROVIDER", "groq")
    os.environ["LLM_PROVIDER"] = provider

    key_name = "GROQ_API_KEY"

    if not os.environ.get(key_name):
        api_key = questionary.password(
            f"{key_name} not found. Enter your API key (will be saved for future runs):"
        ).ask()
        if not api_key:
            return False
        os.environ[key_name] = api_key
        with open(ENV_FILE, "a") as f:
            f.write(f"{key_name}={api_key}\n")
    return True


def ensure_dirs():
    os.makedirs(SAMPLES_DIR, exist_ok=True)
    os.makedirs(WORK_DIR, exist_ok=True)


def load_apk():
    apk_path = questionary.path("Enter the path to the APK file:").ask()
    if not apk_path or not os.path.exists(apk_path):
        console.print("[bold red]Invalid path or file does not exist.[/bold red]")
        return

    if not apk_path.endswith(".apk"):
        console.print("[bold red]File must be an .apk[/bold red]")
        return

    ensure_dirs()
    dest = os.path.join(SAMPLES_DIR, os.path.basename(apk_path))
    try:
        shutil.copy2(apk_path, dest)
        console.print(f"[bold green]Successfully copied to {dest}[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Failed to copy file: {e}[/bold red]")


def run_static_analysis():
    ensure_dirs()
    apks = glob.glob(os.path.join(SAMPLES_DIR, "*.apk"))
    if not apks:
        console.print(
            f"[bold red]No APKs found in {SAMPLES_DIR}. Please load an APK first.[/bold red]"
        )
        return

    try:
        with console.status(
            "[bold white]Building APKPhage Docker image (incremental)...[/bold white]",
            spinner="dots",
        ):
            subprocess.run(
                ["docker", "build", "-t", "apk-analyzer", "."],
                cwd=package_dir,
                check=True,
                capture_output=True,
            )
    except subprocess.CalledProcessError as e:
        console.print("[bold red]Failed to build Docker image.[/bold red]")
        err_msg = e.stderr.decode("utf-8", errors="ignore")
        console.print(err_msg)
        if "permission denied" in err_msg.lower():
            console.print(
                "\n[bold white]Hint: Your user doesn't have permission to run Docker.[/bold white]"
            )
            console.print("Run this command to fix it, then restart your terminal:")
            console.print("  [bold cyan]sudo usermod -aG docker $USER[/bold cyan]")
            console.print(
                "Or just run [bold cyan]newgrp docker[/bold cyan] in this terminal session before running the CLI."
            )
        return

    cmd = [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "-v",
        f"{SAMPLES_DIR}:/app/samples:ro",
        "-v",
        f"{WORK_DIR}:/app/work",
        "apk-analyzer",
    ]
    try:
        _run_analyzer_live(cmd, package_dir)
        console.print("[bold green][+] Static analysis complete.[/bold green]")

        # Fix file ownership since Docker runs as root
        if sys.platform != "win32":
            try:
                uid = os.getuid()
                gid = os.getgid()
                subprocess.run(
                    ["sudo", "chown", "-R", f"{uid}:{gid}", WORK_DIR], stderr=subprocess.DEVNULL
                )
            except Exception:
                pass

        # Auto-run AI if key is present or user accepts
        if (
            os.environ.get("GROQ_API_KEY")
            or os.environ.get("LLM_PROVIDER") == "groq"
            or questionary.confirm("Do you want to automatically run the AI summarizer now?").ask()
        ):
            if get_or_prompt_api_key():
                stages = glob.glob(os.path.join(WORK_DIR, "*", "llm_stage.json"))
                for stage in stages:
                    rel_stage = os.path.relpath(stage, WORK_DIR)
                    console.print(
                        f"[bold white][*] Auto-running AI Summarizer for {rel_stage}...[/bold white]"
                    )
                    try:
                        from apkphage import ai_summarizer

                        with console.status(
                            f"[bold white]Summarizing {rel_stage}...[/bold white]", spinner="dots"
                        ):
                            ai_summarizer.summarize_stage(stage)
                        console.print(
                            f"[bold green][+] AI Summarization complete for {rel_stage}[/bold green]"
                        )
                    except Exception as e:
                        console.print(
                            f"[bold red]Failed to run AI summarizer for {rel_stage}: {e}[/bold red]"
                        )
        else:
            console.print(
                "[bold green]Check 'Generate AI Report' or 'View Report' in the menu.[/bold green]"
            )

    except subprocess.CalledProcessError as e:
        console.print("[bold red]Static analysis failed.[/bold red]")
        err_msg = e.stderr.decode("utf-8", errors="ignore")
        console.print(err_msg)
        if "permission denied" in err_msg.lower():
            console.print(
                "\n[bold white]Hint: Your user doesn't have permission to run Docker.[/bold white]"
            )
            console.print(
                "Run: [bold cyan]sudo usermod -aG docker $USER[/bold cyan] and then [bold cyan]newgrp docker[/bold cyan]"
            )


def generate_ai_report():
    if not get_or_prompt_api_key():
        console.print("[bold red]API Key is required to run the AI summarizer.[/bold red]")
        return

    # Fix file ownership since Docker runs as root
    if sys.platform != "win32":
        try:
            uid = os.getuid()
            gid = os.getgid()
            subprocess.run(
                ["sudo", "chown", "-R", f"{uid}:{gid}", WORK_DIR], stderr=subprocess.DEVNULL
            )
        except Exception:
            pass

    # Find llm_stage.json files
    stages = glob.glob(os.path.join(WORK_DIR, "*", "llm_stage.json"))
    if not stages:
        console.print(
            "[bold red]No pending AI stages (llm_stage.json) found. Run static analysis first.[/bold red]"
        )
        return

    choices = [os.path.relpath(s, WORK_DIR) for s in stages]
    selected = questionary.select("Select the analysis stage to summarize:", choices=choices).ask()
    if not selected:
        return

    stage_path = os.path.join(WORK_DIR, selected)

    try:
        from apkphage import ai_summarizer

        with console.status(
            f"[bold white]Running AI Summarizer for {selected}...[/bold white]", spinner="dots"
        ):
            ai_summarizer.summarize_stage(stage_path)
        console.print(f"[bold green][+] AI Summarization complete for {selected}[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Failed to run AI summarizer: {e}[/bold red]")


def view_report():
    reports = glob.glob(os.path.join(WORK_DIR, "*", "report.json"))
    if not reports:
        console.print("[bold red]No reports found. Generate an AI report first.[/bold red]")
        return

    choices = [os.path.relpath(r, WORK_DIR) for r in reports]
    selected = questionary.select("Select a report to view:", choices=choices).ask()
    if not selected:
        return

    report_path = os.path.join(WORK_DIR, selected)
    with open(report_path) as f:
        data = json.load(f)

    sample_name = data.get("sample", "Unknown")
    synthesis = data.get("final_synthesis", {})

    if isinstance(synthesis, str):
        console.print(
            f"[yellow]Report for {sample_name} has pending AI summary. Run 'Generate AI Report'.[/yellow]"
        )
        return

    console.print(
        Panel(
            f"[bold cyan]Executive Summary for {sample_name}[/bold cyan]\n"
            + synthesis.get("executive_summary", "N/A")
        )
    )

    # Classifications
    classifications = synthesis.get("malware_classification", [])
    console.print(f"[bold red]Classification:[/bold red] {', '.join(classifications)}")

    # IOCs
    iocs = synthesis.get("iocs", [])
    if iocs:
        ioc_table = Table(title="Indicators of Compromise (IOCs)")
        ioc_table.add_column("IOC", style="magenta")
        for ioc in iocs:
            ioc_table.add_row(str(ioc))
        console.print(ioc_table)

    # Next Steps
    next_steps = synthesis.get("recommended_next_steps", [])
    if next_steps:
        console.print("[bold blue]Recommended Next Steps:[/bold blue]")
        for step in next_steps:
            console.print(f" - {step}")


def _kvm_available() -> bool:
    if sys.platform != "win32" and os.path.exists("/dev/kvm"):
        return True
    # Docker Desktop on Windows/macOS: expose the VM's /dev/kvm via opt-in.
    return os.environ.get("APKPHAGE_SANDBOX_KVM") == "1"


def _ensure_emulator_image() -> str:
    """Build apkphage-emulator from Dockerfile.sandbox lazily (big first build)."""
    if (
        subprocess.run(
            ["docker", "image", "inspect", "apkphage-emulator"], capture_output=True
        ).returncode
        == 0
    ):
        return "apkphage-emulator"
    dockerfile = os.path.join(package_dir, "Dockerfile.sandbox")
    if not os.path.exists(dockerfile):
        console.print(
            "[bold red]Dockerfile.sandbox not found - cannot build the emulator sandbox.[/bold red]"
        )
        raise SystemExit(1)
    console.print(
        "[bold white][*] Building apkphage-emulator (first build downloads ~1GB of Android SDK - be patient)...[/bold white]"
    )
    try:
        subprocess.run(
            ["docker", "build", "-t", "apkphage-emulator", "-f", "Dockerfile.sandbox", "."],
            cwd=package_dir,
            check=True,
        )
    except subprocess.CalledProcessError:
        console.print(
            "[bold red]Failed to build the emulator image. Check the build log above.[/bold red]"
        )
        raise SystemExit(1) from None
    return "apkphage-emulator"


def _stream_sandbox_logs(console_override=None):
    """Tail apkphage-sandbox logs in a daemon thread, printing each line.

    Gives the operator a live, honest window into the emulator (QEMU boot,
    package manager, dex2oat, install) while the analyzer runs. Dies with the
    process automatically. Accepts a console override so it can print into a
    rich Live region."""
    out_console = console_override or console

    try:
        proc = subprocess.Popen(
            ["docker", "logs", "--tail", "30", "-f", "apkphage-sandbox"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except Exception:
        return None

    def _tail():
        try:
            for line in iter(proc.stdout.readline, ""):
                line = line.rstrip()
                if line:
                    out_console.print(f"[dim cyan][sandbox][/dim cyan] {line}")
        except Exception:
            pass

    t = threading.Thread(target=_tail, daemon=True)
    t.start()
    return t


def _pipeline_status():
    """Read the analyzer's latest live phase report from the work mount."""
    paths = glob.glob(os.path.join(WORK_DIR, "*", "pipeline_status.json"))
    if not paths:
        return None
    try:
        with open(paths[0], encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


_STATE_SYMBOL = {
    "pending": "[dim]·[/dim]",
    "running": "[bold cyan]●[/bold cyan]",
    "done": "[bold green]✓[/bold green]",
    "failed": "[bold red]✗[/bold red]",
}


def _master_panel(status):
    """Build the bottom-pinned master progress panel from live status."""
    if not status:
        return Panel(
            "[dim]Waiting for the analyzer to report phase state...[/dim]",
            title="MASTER PROGRESS",
            border_style="cyan",
            padding=(0, 1),
        )

    phases = status.get("phases", [])
    total = status.get("elapsed_total", 0)
    pct = status.get("percent", 0)

    mins, secs = divmod(total, 60)
    bar_fill = "█" * (pct // 2)
    bar_rest = "░" * (50 - pct // 2)
    header = f"[bold blue]MASTER PROGRESS[/bold blue]  [cyan]{pct}%[/cyan]  [dim]({mins}m {secs:02d}s)[/dim]"
    bar = f"[cyan]{bar_fill}[/cyan][dim]{bar_rest}[/dim]"

    rows = [header, bar]
    for ph in phases:
        name = ph.get("name", "?")
        state = ph.get("state", "pending")
        elapsed = ph.get("elapsed", 0)
        sym = _STATE_SYMBOL.get(state, _STATE_SYMBOL["pending"])
        if state == "running":
            label = f"[bold]{name}[/bold] [yellow]running {elapsed}s[/yellow]"
        elif state == "done":
            label = f"[green]{name}[/green] [dim]({elapsed}s)[/dim]"
        elif state == "failed":
            label = f"[red]{name}[/red] [red]FAILED[/red]"
        else:
            label = f"[dim]{name} — pending[/dim]"
        rows.append(f"  {sym}  {label}")

    return Panel("\n".join(rows), border_style="cyan", padding=(0, 1))


def _stream_normalize(line):
    """Turn a raw analyzer output chunk into print-worthy lines.

    The container's loaders overwrite in-place with \\r; collapse each chunk to
    its final frame so heartbeats don't pile up on the terminal."""
    out = []
    for part in line.split("\n"):
        part = part.rstrip("\r").strip()
        if not part:
            continue
        frames = part.split("\r")
        out.append(frames[-1])
    return out


def _run_analyzer_live(cmd, cwd):
    """Run the analyzer container beneath a bottom-pinned live progress panel.

    Analyzer/sandbox stdout prints ABOVE the panel (rich groups that output,
    then redraws the live region), so the operator keeps full visibility of the
    pipeline's overall state at all times."""
    import queue

    proc = subprocess.Popen(
        cmd,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    q = queue.Queue()

    def _reader():
        try:
            for line in iter(proc.stdout.readline, ""):
                q.put(line)
        except Exception:
            pass

    threading.Thread(target=_reader, daemon=True).start()

    with Live(
        _master_panel(_pipeline_status()),
        console=console,
        refresh_per_second=4,
        vertical_overflow="visible",
    ) as live:
        _stream_sandbox_logs(console)
        last_key = None
        while proc.poll() is None:
            try:
                line = q.get(timeout=1)
                for part in _stream_normalize(line):
                    console.print(part, highlight=False)
            except queue.Empty:
                status = _pipeline_status()
                key = json.dumps(status) if status else None
                if status and key != last_key:
                    last_key = key
                    live.update(_master_panel(status))

    if proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, cmd)


def _ensure_fakenet_image() -> str:
    """Build apkphage-fakenet from apkphage.dynamic/fakenet_config lazily."""
    if (
        subprocess.run(
            ["docker", "image", "inspect", "apkphage-fakenet"], capture_output=True
        ).returncode
        == 0
    ):
        return "apkphage-fakenet"
    fakenet_dir = os.path.join(package_dir, "dynamic", "fakenet_config")
    if not os.path.exists(os.path.join(fakenet_dir, "Dockerfile")):
        console.print(
            "[bold yellow][!] dynamic/fakenet_config/Dockerfile missing - running sandbox WITHOUT fake internet.[/bold yellow]"
        )
        return None
    console.print("[bold white][*] Building apkphage-fakenet (fake DNS/HTTP sink)...[/bold white]")
    try:
        subprocess.run(
            ["docker", "build", "-t", "apkphage-fakenet", "."],
            cwd=fakenet_dir,
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError:
        console.print(
            "[bold red]Failed to build the fakenet image. Check the build log above.[/bold red]"
        )
        raise SystemExit(1) from None
    return "apkphage-fakenet"


def run_dynamic_analysis():
    ensure_dirs()
    apks = glob.glob(os.path.join(SAMPLES_DIR, "*.apk"))
    if not apks:
        console.print(
            f"[bold red]No APKs found in {SAMPLES_DIR}. Please load an APK first.[/bold red]"
        )
        return

    # Build Analyzer Image
    try:
        with console.status(
            "[bold white]Building APKPhage Analyzer image (incremental)...[/bold white]",
            spinner="dots",
        ):
            subprocess.run(
                ["docker", "build", "-t", "apk-analyzer", "."],
                cwd=package_dir,
                check=True,
                capture_output=True,
            )
    except subprocess.CalledProcessError as e:
        console.print("[bold red]Failed to build Analyzer image.[/bold red]")
        if e.stderr:
            console.print(f"[dim red]{e.stderr.decode('utf-8', errors='ignore')}[/dim red]")
        return

    console.print(
        "[bold white][*] Choosing a platform-friendly sandbox for this host...[/bold white]"
    )

    # Fast path (Linux only): Redroid container Android - needs binder devices.
    has_binder = os.path.exists("/dev/binderfs") or os.path.exists("/dev/binder")
    if sys.platform != "win32" and has_binder:
        console.print(
            "[bold green]  + Binder devices found - using Redroid (fast container Android).[/bold green]"
        )
        sandbox_image = "redroid/redroid:11.0.0-latest"
        sandbox_extra = ["-v", "/dev/binderfs:/dev/binderfs"]
        sandbox_cmd = ["androidboot.hardware=redroid"]
    else:
        # Platform-friendly path (Windows/macOS/Linux): real Android emulator
        # via Dockerfile.sandbox. Accelerated with KVM when present, otherwise
        # software emulation (slow but portable - no binder/ashmem required).
        console.print(
            "[bold yellow]  - No binder devices - using Android emulator image (KVM if available, else software).[/bold yellow]"
        )
        sandbox_image = _ensure_emulator_image()
        sandbox_extra = ["--device", "/dev/kvm"] if _kvm_available() else []
        sandbox_cmd = []

    # Kill any existing sandbox first so the network isn't in use
    subprocess.run(["docker", "rm", "-f", "apkphage-sandbox"], capture_output=True)
    subprocess.run(["docker", "rm", "-f", "apk-analyzer-dynamic"], capture_output=True)
    subprocess.run(["docker", "rm", "-f", "apkphage-fakenet"], capture_output=True)

    # Ensure clean network state
    subprocess.run(["docker", "network", "rm", "apkphage-net"], capture_output=True)
    try:
        subprocess.run(
            ["docker", "network", "create", "apkphage-net"], capture_output=True, check=True
        )
    except subprocess.CalledProcessError:
        pass  # If it still fails, it probably already exists and is fine

    # Fakenet (fake internet sink) joins the sandbox network when available.
    # Only meaningful for the emulator path (redroid is Linux-only binder).
    fakenet_env = []
    if sys.platform == "win32" or not has_binder:
        fakenet_image = _ensure_fakenet_image()
        if fakenet_image:
            try:
                subprocess.run(
                    [
                        "docker",
                        "run",
                        "-d",
                        "--rm",
                        "--name",
                        "apkphage-fakenet",
                        "--network",
                        "apkphage-net",
                        "-v",
                        f"{WORK_DIR}:/app/work",
                        "-e",
                        "FAKENET_LOG=/app/work/fakenet_requests.log",
                        fakenet_image,
                    ],
                    check=True,
                    capture_output=True,
                )
                fakenet_env = ["-e", "FAKENET_HOST=apkphage-fakenet"]
                console.print(
                    "[bold green]  + Fake internet sink online (DNS/HTTP/HTTPS -> fakenet).[/bold green]"
                )
            except subprocess.CalledProcessError as e:
                console.print(
                    "[bold yellow][!] Could not start fakenet - continuing without it.[/bold yellow]"
                )
                if e.stderr:
                    console.print(
                        f"[dim yellow]{e.stderr.decode('utf-8', errors='ignore')}[/dim yellow]"
                    )

    # Start Sandbox
    try:
        subprocess.run(
            [
                "docker",
                "run",
                "-d",
                "--rm",
                "--name",
                "apkphage-sandbox",
                "--privileged",
                "--network",
                "apkphage-net",
                "-v",
                f"{WORK_DIR}:/app/work",
                "-e",
                "CAPTURE_NET=1",
            ]
            + fakenet_env
            + sandbox_extra
            + [sandbox_image]
            + sandbox_cmd,
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError as e:
        console.print("[bold red]Failed to start the sandbox container.[/bold red]")
        if e.stderr:
            console.print(f"[dim red]{e.stderr.decode('utf-8', errors='ignore')}[/dim red]")
        return

    try:
        console.print(
            "[bold white][*] Sandbox container started. Boot is verified inside the analyzer stage (bounded wait, no hang).[/bold white]"
        )

        cmd = [
            "docker",
            "run",
            "--rm",
            "--name",
            "apk-analyzer-dynamic",
            "--network",
            "apkphage-net",
            "-e",
            "HOST_IP=apkphage-sandbox",
            "-v",
            f"{SAMPLES_DIR}:/app/samples:ro",
            "-v",
            f"{WORK_DIR}:/app/work",
            "apk-analyzer",
            "--dynamic",
        ]

        console.print(
            "[bold white]Starting Full Analysis Pipeline (Static -> Emulation -> Frida)...[/bold white]"
        )
        _run_analyzer_live(cmd, package_dir)
        console.print("[bold green][+] Analysis complete. Logs saved in work/[/bold green]")

        # Fix file ownership
        if sys.platform != "win32":
            try:
                uid = os.getuid()
                gid = os.getgid()
                subprocess.run(
                    ["sudo", "chown", "-R", f"{uid}:{gid}", WORK_DIR], stderr=subprocess.DEVNULL
                )
            except Exception:
                pass

        # Auto-run AI if key is present
        if os.environ.get("GROQ_API_KEY") or os.environ.get("LLM_PROVIDER") == "groq":
            if get_or_prompt_api_key():
                stages = glob.glob(os.path.join(WORK_DIR, "*", "llm_stage.json"))
                for stage in stages:
                    rel_stage = os.path.relpath(stage, WORK_DIR)
                    console.print(
                        f"[bold white][*] Auto-running AI Summarizer for {rel_stage}...[/bold white]"
                    )
                    from apkphage import ai_summarizer

                    try:
                        ai_summarizer.summarize_stage(stage)
                    except Exception as e:
                        console.print(
                            f"[bold yellow][!] AI summarizer failed: {e.__class__.__name__}: {e}[/bold yellow]"
                        )

    except subprocess.CalledProcessError as e:
        console.print("[bold red]Analysis failed.[/bold red]")
        if e.stderr:
            console.print(f"[dim red]{e.stderr.decode('utf-8', errors='ignore')}[/dim red]")
    finally:
        # Keep-sandbox-alive mode: leave the emulator + fakenet + network up so
        # the analyst can interact (adb shell, install other tools, retry hooks)
        # without waiting another ~11min software-emulation boot.
        keep = os.environ.get("APKPHAGE_KEEP_SANDBOX") == "1"
        if keep:
            console.print(
                "[bold yellow][*] APKPHAGE_KEEP_SANDBOX=1 - leaving sandbox running.[/bold yellow]"
            )
            console.print("    The sandbox stays on the apkphage-net network.")
            console.print("    Interact via Docker:  docker exec -it apkphage-sandbox sh")
            console.print(
                "    Tear down:  docker stop apkphage-sandbox apkphage-fakenet; "
                "docker network rm apkphage-net"
            )
        else:
            console.print("[bold white][*] Destroying sandbox and network...[/bold white]")
            subprocess.run(["docker", "stop", "apkphage-sandbox"], capture_output=True)
            subprocess.run(["docker", "stop", "apkphage-fakenet"], capture_output=True)
            subprocess.run(["docker", "network", "rm", "apkphage-net"], capture_output=True)


def main():
    os.chdir(package_dir)

    style = questionary.Style(
        [
            ("qmark", "fg:#007acc bold"),
            ("question", "bold"),
            ("answer", "fg:#007acc bold"),
            ("pointer", "fg:#007acc bold"),
            ("highlighted", "fg:#007acc bold"),
            ("selected", "fg:#007acc bold"),
            ("separator", "fg:#cc5454"),
            ("instruction", "fg:#808080"),
            ("text", ""),
            ("disabled", "fg:#858585 italic"),
        ]
    )

    while True:
        os.system("cls" if os.name == "nt" else "clear")
        print_banner()

        choice = questionary.select(
            "Select action:",
            choices=[
                questionary.Choice("Load APK File", value="1"),
                questionary.Choice("Run Static Analysis (Docker)", value="2"),
                questionary.Choice("Run Full Pipeline (Static + Dynamic + Sandbox)", value="3"),
                questionary.Choice("Generate AI Report", value="4"),
                questionary.Choice("View Report", value="5"),
                questionary.Choice("Exit", value="6"),
            ],
            style=style,
            qmark="",
            pointer="❯",
            use_indicator=True,
        ).ask()

        if choice is None or choice == "6":
            console.print("[bold green]Exiting. Stay safe![/bold green]")
            break
        elif choice == "1":
            load_apk()
        elif choice == "2":
            run_static_analysis()
        elif choice == "3":
            run_dynamic_analysis()
        elif choice == "4":
            generate_ai_report()
        elif choice == "5":
            view_report()

        input("\nPress Enter to return to the menu...")


if __name__ == "__main__":
    main()
