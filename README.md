# Frida iOS Mach-O Decryptor

A Python tool to decrypt and dump the executable code of iOS applications running on jailbroken devices.

I've been dissatisfied with existing iOS app decryption tools for a while. Many are outdated and don't handle rootless jailbreaks well, or don't work on newer iOS versions.

This tool automates the "clutching" process: it locates the encrypted `__TEXT` segment in memory, dumps the decrypted bytes using Frida, and surgically patches a local copy of the binary. It utilizes a hybrid approach (Raw I/O + LIEF) to ensure the binary is immediately ready for static analysis in tools like Binary Ninja, IDA Pro, or Ghidra.

## Features

* **Auto-Pull Binary:** Automatically downloads the encrypted binary from the device - no manual SCP required.
* **Full Automation:** Dumps decrypted code and updates the Mach-O header (`cryptid=0`) in one pass.
* **Module Targeting:** Can decrypt the main app executable or specific encrypted frameworks/dylibs.
* **Hybrid Patching:**
  * Uses Raw I/O for precise, safe injection of code bytes.
  * Uses LIEF for safe parsing and modification of header metadata.
* **Rootless Compatible:** Works on both rootful and rootless jailbreaks (Palera1n, Dopamine, etc.) on iOS 15-18.
* **Frida 17+ Compatible:** Updated to use the latest Frida JavaScript API.
* **Analysis Ready:** The output file opens directly in disassemblers without encryption warnings.

## Installation

### Using pipx (Recommended)

Install the tool globally using pipx:

```bash
pipx install .
```

This makes the `frida-decrypt` command available from any directory.

To update after making changes:

```bash
pipx install --force .
```

To uninstall:

```bash
pipx uninstall frida-decrypt
```

### Manual Installation

Alternatively, install with pip:

```bash
pip install .
```

## Prerequisites

### On the Host Machine

* Python 3.8 or later
* pipx (recommended) or pip

### On the Jailbroken Device

* Frida Server must be running.
  * Rootless: Install `frida-server` via Sileo/Zebra.
  * Verification: Run `frida-ps -U` from your host machine to confirm connectivity.

## Usage

### 1. Auto-Pull and Decrypt (Recommended)

The simplest method - automatically pulls the binary from the device and decrypts it:

```bash
frida-decrypt "<Process Name>"
```

Example:

```bash
frida-decrypt Instagram
```

Result: Downloads `Instagram` from device and creates `Instagram_decrypted` ready for analysis.

### 2. Using a Local Binary

If you already have the encrypted binary locally:

```bash
frida-decrypt "<Process Name>" -l "<Local Binary Path>"
```

Example:

```bash
frida-decrypt Instagram -l ./Instagram
```

### 3. Decrypting a Specific Dylib / Framework

Use this if the main logic is hidden inside an encrypted framework or dynamic library:

```bash
frida-decrypt "<Process Name>" -m "<Module Name>"
```

Example:

```bash
frida-decrypt Instagram -m SomeFramework
```

### 4. Custom Output Directory

Specify where to save the downloaded and decrypted binaries:

```bash
frida-decrypt Instagram -o ./output
```

## Command Line Options

```bash
positional arguments:
  process               Name of the running process on the device

optional arguments:
  -l, --local-binary    Path to local encrypted binary (skip download)
  -m, --module          Specific module/dylib name to dump
  -o, --output-dir      Output directory (default: current directory)
```

## How It Works

1. **Attach:** The script connects to the running app process on the device via USB.
2. **Download (optional):** Uses Frida to read the encrypted binary directly from the device filesystem.
3. **Locate:** Injects JavaScript to parse the Mach-O headers in memory, finding the `LC_ENCRYPTION_INFO_64` command.
4. **Dump:** Reads the decrypted bytes from RAM.
5. **Patch:**
   * Uses standard file I/O to overwrite the encrypted bytes in the local file with the dumped data.
   * Uses LIEF to set `cryptid` to `0`, marking the file as decrypted.

## Troubleshooting

* **`Error attaching to process...`**
  * Ensure the app is running in the foreground.
  * Use `frida-ps -U` to verify the exact process name.

* **`LIEF Error: ...`**
  * The script will still inject the raw bytes. You may need to manually hex-edit the `cryptid` flag to `00`.

* **Binary download fails**
  * Ensure Frida server is running on the device.
  * Try using `-l` with a manually transferred binary via SCP.

## Requirements

* Frida 17.0.0 or later
* Python 3.8 or later
* LIEF library
