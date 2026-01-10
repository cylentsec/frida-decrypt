import frida
import sys
import os
import argparse
import lief

# -----------------------------------------------------------------------------
# THE FRIDA JAVASCRIPT PAYLOAD
# -----------------------------------------------------------------------------
FRIDA_SCRIPT = """
var CHUNK_SIZE = 1024 * 1024; // 1MB chunks for file transfer

rpc.exports = {
    // Get the path to the target module's binary on disk
    // JS camelCase -> Python snake_case (Frida 17+ convention)
    getModulePath: function(targetModuleName) {
        var targetModule = null;
        
        if (targetModuleName) {
            var modules = Process.enumerateModules();
            // Exact match first
            for (var i = 0; i < modules.length; i++) {
                if (modules[i].name === targetModuleName) {
                    targetModule = modules[i];
                    break;
                }
            }
            // Partial match fallback
            if (!targetModule) {
                for (var i = 0; i < modules.length; i++) {
                    if (modules[i].name.indexOf(targetModuleName) !== -1) {
                        targetModule = modules[i];
                        break;
                    }
                }
            }
        } else {
            targetModule = Process.mainModule;
        }
        
        if (!targetModule) {
            return null;
        }
        
        return {
            name: targetModule.name,
            path: targetModule.path,
            base: targetModule.base.toString(),
            size: targetModule.size
        };
    },
    
    // Get file size using stat (getFileSize -> get_file_size in Python)
    // Frida 17+: Use Module.getGlobalExportByName() instead of Module.findExportByName(null, ...)
    getFileSize: function(filePath) {
        var statAddr = Module.getGlobalExportByName('stat');
        
        var statFunc = new NativeFunction(statAddr, 'int', ['pointer', 'pointer']);
        
        var pathPtr = Memory.allocUtf8String(filePath);
        // stat struct is ~144 bytes on arm64, st_size is at offset 96
        var statBuf = Memory.alloc(144);
        
        var result = statFunc(pathPtr, statBuf);
        if (result !== 0) {
            send({"type": "error", "message": "stat() failed for: " + filePath + " (result=" + result + ")"});
            return -1;
        }
        
        // st_size is at offset 96 on arm64 iOS (int64)
        var size = statBuf.add(96).readS64();
        return size;
    },
    
    // Read a chunk of the file using open/read/close (readFileChunk -> read_file_chunk in Python)
    // Frida 17+: Use Module.getGlobalExportByName() instead of Module.findExportByName(null, ...)
    readFileChunk: function(filePath, offset, chunkSize) {
        var openFunc = new NativeFunction(Module.getGlobalExportByName('open'), 'int', ['pointer', 'int']);
        var readFunc = new NativeFunction(Module.getGlobalExportByName('read'), 'long', ['int', 'pointer', 'long']);
        var lseekFunc = new NativeFunction(Module.getGlobalExportByName('lseek'), 'long', ['int', 'long', 'int']);
        var closeFunc = new NativeFunction(Module.getGlobalExportByName('close'), 'int', ['int']);
        
        var pathPtr = Memory.allocUtf8String(filePath);
        var O_RDONLY = 0;
        
        var fd = openFunc(pathPtr, O_RDONLY);
        if (fd < 0) {
            send({"type": "error", "message": "Failed to open file: " + filePath + " (fd=" + fd + ")"});
            return null;
        }
        
        // Seek to offset
        var SEEK_SET = 0;
        lseekFunc(fd, offset, SEEK_SET);
        
        // Read chunk
        var buffer = Memory.alloc(chunkSize);
        var bytesRead = readFunc(fd, buffer, chunkSize);
        closeFunc(fd);
        
        if (bytesRead <= 0) {
            send({"type": "error", "message": "read() returned " + bytesRead});
            return null;
        }
        
        return buffer.readByteArray(bytesRead);
    },
    
    dumpDecryptedSegment: function(targetModuleName) {
        var modules = Process.enumerateModules();
        var targetModule = null;

        if (targetModuleName) {
            // Search for module by name (exact match first, then partial)
            for (var i = 0; i < modules.length; i++) {
                if (modules[i].name === targetModuleName) {
                    targetModule = modules[i];
                    break;
                }
            }
            // Fallback to partial match if exact match not found
            if (!targetModule) {
                for (var i = 0; i < modules.length; i++) {
                    if (modules[i].name.indexOf(targetModuleName) !== -1) {
                        targetModule = modules[i];
                        break;
                    }
                }
            }
            if (!targetModule) {
                send({"type": "error", "message": "Module not found: " + targetModuleName});
                send({"type": "debug", "message": "Available modules: " + modules.slice(0, 10).map(function(m) { return m.name; }).join(", ")});
                return null;
            }
        } else {
            // Default to main executable - find by process name or first non-dylib
            var mainModule = Process.mainModule;
            if (mainModule) {
                targetModule = mainModule;
            } else {
                // Fallback: first module that's not a dylib
                for (var i = 0; i < modules.length; i++) {
                    if (!modules[i].name.endsWith('.dylib')) {
                        targetModule = modules[i];
                        break;
                    }
                }
                if (!targetModule) targetModule = modules[0];
            }
        }

        var baseAddress = targetModule.base;
        send({"type": "debug", "message": "Module base: " + baseAddress + ", name: " + targetModule.name});
        
        // Mach-O Header Parsing to find LC_ENCRYPTION_INFO_64
        // Header (32 bytes) -> Load Commands
        var ncmds = baseAddress.add(16).readU32();
        var cmdPtr = baseAddress.add(32);
        
        send({"type": "debug", "message": "Parsing " + ncmds + " load commands"});
        
        for (var i = 0; i < ncmds; i++) {
            var cmd = cmdPtr.readU32();
            var cmdSize = cmdPtr.add(4).readU32();
            
            // LC_ENCRYPTION_INFO_64 = 0x2C, LC_ENCRYPTION_INFO = 0x21
            if (cmd === 0x2C || cmd === 0x21) {
                var cryptOff = cmdPtr.add(8).readU32();
                var cryptSize = cmdPtr.add(12).readU32();
                var cryptId = cmdPtr.add(16).readU32();
                
                send({
                    "type": "info", 
                    "cryptoff": cryptOff, 
                    "cryptsize": cryptSize, 
                    "cryptid": cryptId,
                    "module": targetModule.name,
                    "base": baseAddress.toString()
                });
                
                // Read the DECRYPTED bytes from memory
                // In running iOS processes, the system decrypts in memory (cryptid shows original value)
                try {
                    var memoryAddress = baseAddress.add(cryptOff);
                    send({"type": "debug", "message": "Reading " + cryptSize + " bytes from " + memoryAddress});
                    var decryptedBytes = memoryAddress.readByteArray(cryptSize);
                    
                    if (decryptedBytes === null) {
                        send({"type": "error", "message": "Failed to read memory at " + memoryAddress});
                        return null;
                    }
                    
                    send({"type": "debug", "message": "Successfully read " + decryptedBytes.byteLength + " bytes"});
                    return decryptedBytes;
                } catch (e) {
                    send({"type": "error", "message": "Exception reading memory: " + e.message});
                    return null;
                }
            }
            cmdPtr = cmdPtr.add(cmdSize);
        }
        send({"type": "error", "message": "No LC_ENCRYPTION_INFO found"});
        return null;
    }
};
"""


# -----------------------------------------------------------------------------
# PYTHON HOST LOGIC
# -----------------------------------------------------------------------------
CHUNK_SIZE = 1024 * 1024  # 1MB chunks


def pull_binary_from_device(script, module_name, output_dir="."):
    """Pull the encrypted binary from the device using Frida file operations."""
    
    # Get module info
    print(f"[*] Getting module path from device...")
    module_info = script.exports_sync.get_module_path(module_name)
    
    if module_info is None:
        print(f"[!] Could not find module on device")
        return None
    
    remote_path = module_info["path"]
    module_name = module_info["name"]
    print(f"[*] Found module: {module_name}")
    print(f"    Remote path: {remote_path}")
    
    # Get file size
    file_size = script.exports_sync.get_file_size(remote_path)
    # Frida may return int64 as string, convert it
    file_size = int(file_size)
    if file_size < 0:
        print(f"[!] Could not get file size for: {remote_path}")
        return None
    
    print(f"    Size: {file_size} bytes ({file_size / 1024 / 1024:.2f} MB)")
    
    # Create output path
    local_path = os.path.join(output_dir, module_name)
    
    # Download file in chunks
    print(f"[*] Downloading binary to: {local_path}")
    downloaded = 0
    
    with open(local_path, "wb") as f:
        while downloaded < file_size:
            remaining = file_size - downloaded
            chunk_size = min(CHUNK_SIZE, remaining)
            
            chunk = script.exports_sync.read_file_chunk(remote_path, downloaded, chunk_size)
            if chunk is None:
                print(f"\n[!] Failed to read chunk at offset {downloaded}")
                return None
            
            f.write(chunk)
            downloaded += len(chunk)
            
            # Progress indicator
            progress = (downloaded / file_size) * 100
            print(f"\r    Progress: {progress:.1f}% ({downloaded}/{file_size} bytes)", end="", flush=True)
    
    print()  # Newline after progress
    print(f"[*] Download complete: {local_path}")
    
    return local_path


def dump_memory(script, module_name):
    """Sync wrapper for RPC call"""
    # Frida converts JS camelCase (dumpDecryptedSegment) to Python snake_case (dump_decrypted_segment)
    return script.exports_sync.dump_decrypted_segment(module_name)


def main():
    parser = argparse.ArgumentParser(
        description="Frida iOS Decryptor (Mach-O)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Auto-pull binary from device and decrypt:
  %(prog)s Front
  
  # Use a local binary (skip download):
  %(prog)s Front -l ./Front
  
  # Decrypt a specific framework/dylib:
  %(prog)s Front -m SomeFramework
"""
    )
    parser.add_argument(
        "process", help="Name of the running process on the device (e.g. 'Instagram')"
    )
    parser.add_argument(
        "-l", "--local-binary",
        help="Path to local encrypted binary (if not provided, will pull from device)",
        default=None,
    )
    parser.add_argument(
        "-m",
        "--module",
        help="Specific module/dylib name to dump (Optional, defaults to main executable)",
        default=None,
    )
    parser.add_argument(
        "-o", "--output-dir",
        help="Output directory for downloaded/decrypted binaries (default: current directory)",
        default=".",
    )

    args = parser.parse_args()

    # 1. Attach to Device
    print(f"[*] Connecting to device...")
    try:
        device = frida.get_usb_device()
        session = device.attach(args.process)
    except Exception as e:
        print(f"[!] Error attaching to '{args.process}': {e}")
        print("    Ensure the app is running in the foreground on the device.")
        sys.exit(1)

    print(f"[*] Attached. Injecting payload...")
    script = session.create_script(FRIDA_SCRIPT)

    # State to hold info from JS
    crypt_details = {}

    def on_message(message, data):
        if message["type"] == "send":
            payload = message["payload"]
            msg_type = payload.get("type")
            if msg_type == "info":
                crypt_details.update(payload)
                print(f"[*] Found Encrypted Segment in '{payload['module']}':")
                print(f"    - Base:     {payload.get('base', 'N/A')}")
                print(f"    - Offset:   0x{payload['cryptoff']:X}")
                print(f"    - Size:     0x{payload['cryptsize']:X} ({payload['cryptsize']} bytes)")
                print(f"    - CryptID:  {payload['cryptid']}")
            elif msg_type == "debug":
                print(f"[DEBUG] {payload['message']}")
            elif msg_type == "error":
                print(f"[ERROR] {payload['message']}")
        elif message["type"] == "error":
            print(f"[!] Script error: {message.get('description', 'Unknown error')}")

    script.on("message", on_message)
    script.load()

    # 2. Get local binary (either pull from device or use provided path)
    local_binary = args.local_binary
    
    if local_binary is None:
        # Pull binary from device
        local_binary = pull_binary_from_device(script, args.module, args.output_dir)
        if local_binary is None:
            print(f"[!] Failed to pull binary from device")
            session.detach()
            sys.exit(1)
    else:
        # Validate provided local binary exists
        if not os.path.exists(local_binary):
            print(f"[!] File not found: {local_binary}")
            session.detach()
            sys.exit(1)

    # 3. Dump Memory
    print(f"[*] Dumping decrypted RAM...")
    try:
        decrypted_data = dump_memory(script, args.module)
    except Exception as e:
        print(f"[!] Failed to call RPC function: {e}")
        session.detach()
        sys.exit(1)

    if decrypted_data is None:
        print("[!] No encrypted data returned.")
        if crypt_details.get("cryptid") == 0:
            print(
                "    Reason: The binary reports it is already unencrypted (cryptid=0)."
            )
        else:
            print("    Reason: Could not find LC_ENCRYPTION_INFO_64 or module name.")
        session.detach()
        sys.exit(1)

    print(f"[*] Dumped {len(decrypted_data)} decrypted bytes from memory.")
    
    # Verify we got actual data
    if len(decrypted_data) == 0:
        print("[!] Received 0 bytes - decryption failed")
        session.detach()
        sys.exit(1)
    
    session.detach()

    # 4. Patching File
    output_path = local_binary + "_decrypted"
    print(f"[*] Patching binary...")

    # A. Inject Bytes (Standard IO)
    with open(local_binary, "rb") as f:
        raw_bin = bytearray(f.read())

    offset = crypt_details["cryptoff"]
    size = crypt_details["cryptsize"]
    
    # Verify size matches
    if len(decrypted_data) != size:
        print(f"[!] Warning: Expected {size} bytes but got {len(decrypted_data)} bytes")
    
    # Check if data is different (basic verification)
    original_encrypted = raw_bin[offset : offset + size]
    if original_encrypted == decrypted_data:
        print("[!] WARNING: Decrypted data is identical to encrypted data!")
        print("    This likely means the app was already decrypted in memory.")

    # Overwrite the encrypted range with our decrypted dump
    raw_bin[offset : offset + size] = decrypted_data

    with open(output_path, "wb") as f:
        f.write(raw_bin)

    # B. Fix Header (LIEF)
    print(f"[*] Updating metadata with LIEF...")
    try:
        binary = lief.parse(output_path)

        # Find the arm64 slice if it's a fat binary (universal)
        # LIEF might open it as a FatBinary or a Binary depending on structure.
        target_binary = None
        if isinstance(binary, lief.MachO.FatBinary):
            for b in binary:
                if b.header.cpu_type == lief.MachO.CPU_TYPES.ARM64:
                    target_binary = b
                    break
        else:
            target_binary = binary

        if target_binary and target_binary.encryption_info:
            target_binary.encryption_info.crypt_id = 0
            binary.write(output_path)  # Write changes back
            print(f"    - cryptid set to 0")
        else:
            print(
                "[!] Warning: Could not locate encryption info with LIEF to set flag."
            )

    except Exception as e:
        print(f"[!] LIEF Error: {e}")
        print(
            "    The bytes are injected, but you may need to manually hex-edit cryptid to 0."
        )

    # Fix permissions
    os.chmod(output_path, 0o755)
    print("-" * 40)
    print(f"[*] SUCCESS. Decrypted binary saved to:\n    {output_path}")
    print("-" * 40)


if __name__ == "__main__":
    main()
