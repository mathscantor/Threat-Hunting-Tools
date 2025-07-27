# Threat-Hunting-Tools
A collection of minimalistic multithreaded scripts to facilitate in offline threat hunting. Happy hunting!

## 1. Logs Extraction

Server administrators may give you logs in a myriad of archive formats. At times, they may give you a multitude of nested archives, making extraction a chore.
Thus, I have created `logs-extractor.py` to help automate this process.
```
usage: logs-extractor.py [-h] -i  -o  [-j ] [-f] [-v] [-l ]

Recursively extracts (nested) compressed logs while keeping original directory tree.

options:
  -h, --help         show this help message and exit
  -i, --input-dir    The directory containing compressed logs
  -o, --output-dir   The directory to extract to
  -j, --threads      The number of threads used for extraction (default: 1)
  -f, --force        Forcefully extract to a non-empty directory.
  -v, --verbose      Show debug logs
  -l, --log-file     Log the progress to a file
```

Supports the following compression type:<br>
1. Zip (`.zip`)`
2. Tar (`.tar`, `.tar.gz`, `.tgz`, `.tar.xz`, `.txz`)
3. XZ (`.xz`)
4. Gzip (`.gz`)


## 2. EVTX Conversion

> Credits: https://github.com/omerbenamram/evtx

If the threat hunt involves some Windows endpoint, windows event logs are commonly given to the blue team for analysis. The static *evtx_dump* binary is found under `bin/${ARCH}/${OS}`.

Supported Architectures and OS:
| Architecture | OS      | evtx_dump       |
|--------------|---------|------------------|
| aarch64      | linux   | ✅ `evtx_dump`   |
|              | macos   | ✅ `evtx_dump`   |
|              | windows | ❌              |
| x86_64       | linux   | ✅ `evtx_dump`   |
|              | macos   | ✅ `evtx_dump`   |
|              | windows | ✅ `evtx_dump.exe` |

```
usage: evtx-converter.py [-h] -i  -o  [-j ] [-t ] [-f] [-v] [-l ]

EVTX conversion is based on evtx_dump utility

options:
  -h, --help         show this help message and exit
  -i, --input-dir    The directory containing EVTX logs
  -o, --output-dir   The directory to store the serialized logs
  -j, --threads      The number of threads used for extraction (default: 1)
  -t, --format       The format of the serialized logs: [jsonl(default), json, xml]
  -f, --force        Forcefully write serialized logs to non-empty directory
  -v, --verbose      Show debug logs
  -l, --log-file     Log the progress to a file

Credits: https://github.com/omerbenamram/evtx
```
> [!TIP]
>
> For those of you who want to cross compile the *evtx_dump* binary yourself:
>
> ```bash
> $ git clone https://github.com/omerbenamram/evtx; cd evtx
> $ rustup target add aarch64-unknown-linux-gnu
> $ sudo apt install gcc-aarch64-linux-gnu
> $ RUSTFLAGS='-C linker=aarch64-linux-gnu-gcc -C target-feature=+crt-static' cargo build --release --target aarch64-unknown-linux-gnu
> ```

## 3. Yara Spray
> Credits: https://github.com/VirusTotal/yara-x

VirusTotal recently made the move to re-write *Yara* fully in rust. This new incarnation intends to be faster, safer and more user-friendly than its predecessor. The static binaries are found in `bin/${ARCH}/${OS}`.

| Architecture | OS      | yara           |
|--------------|---------|----------------|
| aarch64      | linux   |✅ `yara`      |
|              | macos   |✅ `yara`      |
|              | windows |❌             |
| x86_64       | linux   | ✅ `yara`      |
|              | macos   |✅ `yara`      |
|              | windows | ✅ `yara.exe` |

```
usage: yara-spray.py [-h] -i  -y  [-j ] [-v] [-l ]

Yara scan on all logs from a given directory

options:
  -h, --help        show this help message and exit
  -i, --input-dir   The directory containing the plaintext logs
  -y, --yara-rule   The yara rule file.
  -j, --threads     The number of threads used for extraction (default: 1)
  -v, --verbose     Show debug logs
  -l, --log-file    Log the progress to a file

Credits: https://github.com/VirusTotal/yara-x
```
