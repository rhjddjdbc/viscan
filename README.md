# ViScan

**ViScan** is a lightweight malware scanner that detects malicious files by matching file hashes and patterns against known ClamAV signatures. It supports a wide range of ClamAV database formats and performs recursive scanning across directories.

## Features

* Recursive scanning of files and directories
* MD5-based and pattern-based signature matching
* Supports multiple ClamAV signature formats:

  * `.hdb` (MD5)
  * `.fp` (false positives list)
  * `.ndb`, `.ldb`, `.mdb` (pattern-based)
* Skips unsupported or unrecognized formats
* Verbose mode for detailed logs
* Automatic quarantine of detected files
* Automatic download and unpacking of ClamAV signature databases
* Periodic database freshness checks (every 6 weeks)
* Manual force-update option

---

## Building ViScan

To compile the project, run:

```bash
make
```

This will build the `viscan` executable in the root directory.

---

## Directory Structure

```
.
├── database/           # Contains ClamAV signature databases
│   ├── main.cvd
│   ├── daily.cvd
│   ├── main.hdb, .ndb, .ldb, .mdb, .fp, ...
│   └── daily.hdb, .ndb, .ldb, .mdb, .fp, ...
├── quarantine/         # Quarantined malware logs
├── src/                # Source code
│   ├── main.c
│   ├── hash_utils.c/h
│   ├── hdb_parser.c/h
│   ├── quarantine.c/h
│   └── update_database.c/h
├── Makefile
└── viscan              # Compiled binary
```

---

## Supported Signature Formats

| Extension | Description             | Support       |
| --------- | ----------------------- | ------------- |
| `.hdb`    | MD5-based signatures    | Supported     |
| `.fp`     | False positives list    | Supported     |
| `.ndb`    | Pattern-based           | Supported     |
| `.ldb`    | Pattern-based (logical) | Supported     |
| `.mdb`    | Extended pattern rules  | Supported     |
| `.cdb`    | Compressed database     | Ignored       |
| `.sfp`    | Suspicious files list   | Not supported |

Only supported formats are parsed and loaded. Unsupported or unparseable formats are skipped automatically.

---

## ClamAV Databases

ViScan uses the official ClamAV databases:

* [`main.cvd`](https://database.clamav.net/main.cvd)
* [`daily.cvd`](https://database.clamav.net/daily.cvd)

These databases are automatically downloaded and unpacked if missing or outdated.

---

## Database Management

ViScan checks the last modification time of:

* `database/main.cvd`
* `database/daily.cvd`

If either is older than **6 weeks**, it will automatically:

1. Redownload the `.cvd` files
2. Unpack them into the `database/` directory
3. Remove old signature files before extraction

To manually force a refresh, use:

```bash
./viscan --force-update <file_or_dir>
```

---

## Usage

```bash
./viscan [--verbose] [--force-update] <file_or_dir1> [file_or_dir2 ...]
```

### Options

| Option           | Description                                         |
| ---------------- | --------------------------------------------------- |
| `--verbose`      | Enables detailed output during scanning and loading |
| `--force-update` | Forces database update, even if it is up-to-date    |

### Examples

```bash
./viscan --verbose ~/Downloads
./viscan --force-update ./testfile.exe
```

---

## Test Signature (EICAR)

To test detection functionality, you can create the standard [EICAR test file](https://www.eicar.org/download-anti-malware-testfile/) using:

```bash
echo -n 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > eicar.com
```

Then scan it:

```bash
./viscan --verbose ./eicar.com
```

If the signature database is properly loaded, this file will be detected and quarantined.

---

## License

ViScan is licensed under the **GNU General Public License v2.0 (GPLv2)**.
See the `LICENSE` file in the project directory for full details.
