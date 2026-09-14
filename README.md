# APKPhage 🦠
**Automated Android Malware Analysis Pipeline**

APKPhage is an enterprise-grade, fully containerized static and dynamic analysis pipeline for Android malware. It extracts, executes, hooks, and intelligently summarizes suspicious Android applications—all orchestrated through a sleek, professional terminal interface.

---

## 🔥 Features
* **Zero-Emulation Dynamic Sandbox:** Bypasses bloated KVM/QEMU emulators entirely by utilizing native `redroid` (Remote-Android) containers for lightning-fast, hardware-free execution.
* **Air-Gapped Static Analysis:** Safely decompiles malware (via Apktool & Jadx) inside isolated Docker containers without network access to prevent host exploitation.
* **Automated Frida Hooking:** Automatically injects `frida-server`, attaches to the malicious process, and intercepts API calls dynamically over an internal Docker bridge network.
* **AI Threat Intelligence:** Integrates with Groq/Gemini to scan decompiled code, generating a structured threat intelligence report (IOCs, capabilities, classification).
* **Professional Terminal UI:** Built on `rich` and `questionary` for a clean, minimal, and highly interactive user experience.

---

## 🚀 Installation

*Note: You must have **Docker** installed and running on your machine to use APKPhage.*

### Option A: Install via PyPI (Recommended)
If you have Python 3.11+ installed, you can install the CLI globally:
```bash
pip install apkphage
```
Once installed, simply run the tool from anywhere in your terminal:
```bash
apkphage
```

### Option B: Standalone Binary (No Python Required)
1. Navigate to the [Releases page](../../releases/latest).
2. Download the `.zip` archive for your operating system (`apkphage-windows-x64.zip` or `apkphage-linux-x64.zip`).
3. Extract the archive and run the executable (`apkphage.exe`).

---

## 💻 Usage

When you launch `apkphage`, you will be greeted by the interactive terminal menu.

1. **Load APK File**: Select the malware `.apk` you wish to analyze.
2. **Run Full Pipeline**: The tool will automatically:
   * Build the isolated `apk-analyzer` Docker image.
   * Spin up the `redroid` sandbox on the `apkphage-net` network.
   * Execute the Static Analysis (Manifest parsing, high-entropy asset detection).
   * Execute the Dynamic Analysis (Install, launch, and attach Frida hooks).
3. **Generate AI Report**: Enter your LLM API Key (Groq or Gemini) when prompted. The tool will parse the findings and generate a structured `report.json`.

All outputs, decompiled sources, and JSON reports are saved in the `work/<SampleName>/` directory.

---

## 🛠️ For Developers & Contributors

If you want to modify the code, add custom Frida hooks, or develop new features:

```bash
# 1. Clone the repository
git clone https://github.com/pacman-yay/apkphage.git
cd apkphage

# 2. Setup your virtual environment
python -m venv .venv
source .venv/bin/activate  # Or .venv\Scripts\activate on Windows

# 3. Install in editable mode
pip install -e .

# 4. Install pre-commit hooks (DevSecOps)
pip install pre-commit
pre-commit install

# Run the CLI
apkphage
```

### Continuous Deployment (CI/CD)
This project utilizes GitHub Actions for continuous deployment. Creating a new **Release** on GitHub will automatically trigger the pipeline to build standalone binaries and publish the package to PyPI. Code quality and security are enforced locally via `ruff`, `hadolint`, and `gitleaks` pre-commit hooks.
