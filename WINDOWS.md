# HexPath for Windows

The Windows release contains a standalone `hexpath.exe`. Python is not required.

## Install

1. Download `HexPath-Windows-x64.zip` and its `.sha256` file from the latest
   GitHub release.
2. In PowerShell, verify and extract it:

   ```powershell
   Get-FileHash .\HexPath-Windows-x64.zip -Algorithm SHA256
   Expand-Archive .\HexPath-Windows-x64.zip -DestinationPath .\HexPath
   .\HexPath\hexpath.exe --version
   ```

   Compare the displayed hash with the value in
   `HexPath-Windows-x64.zip.sha256` before running the executable.
3. Install the official Windows build of Nmap from
   <https://nmap.org/download.html#windows>. Keep the installer's Npcap option
   enabled. HexPath finds `nmap.exe` on `PATH` and in the standard `Program
   Files`, `Program Files (x86)`, and per-user Nmap directories.

Windows may show a SmartScreen warning because the executable is not currently
code-signed. Verify the SHA-256 checksum, then use **More info > Run anyway**
only if the checksum matches the release asset.

## Run

Use HexPath only against systems you are authorized to test.

```powershell
.\HexPath\hexpath.exe 192.0.2.10 --plan
.\HexPath\hexpath.exe 192.0.2.10 -sV
.\HexPath\hexpath.exe --help
```

`--plan` validates the target and shows the Nmap operation without executing a
scan. Live scans require Nmap; offline graph and saved-assessment commands do
not.

## Build from source

The release workflow builds on a native `windows-latest` GitHub runner because
PyInstaller executables must be built on their target operating system. To
reproduce the executable locally in PowerShell:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install . pyinstaller==6.16.0
.\.venv\Scripts\python.exe -m unittest discover --start-directory tests --verbose
.\.venv\Scripts\python.exe -m PyInstaller --clean --noconfirm --onefile --console --name hexpath --specpath build --paths src src\hexpath\__main__.py
.\dist\hexpath.exe --version
```
