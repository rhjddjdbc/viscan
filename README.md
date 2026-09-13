# ViScan

A lightweight malware scanner for Linux that detects malicious files by
matching MD5 hashes against the official ClamAV signature databases.
Includes an encrypted quarantine vault and automatic database management.

---

## Features

- Recursive scanning of files and directories
- MD5 hash matching against ClamAV `.hdb` databases
- False-positive whitelisting via `.fp` files
- Opt-in Aho-Corasick pattern matching for `.ndb` signatures
- AES-256-GCM encrypted quarantine vault with restore, list, and clean
- Automatic database update with three-tier fallback (direct download →
  `freshclam` → system ClamAV install)
- Atomic updates via temp file + `rename(2)`
- Rate-limit awareness for the ClamAV CDN (HTTP 429)
- Verbose mode and proper exit codes

---

## Building

Install dependencies:

```bash
sudo apt install build-essential libcurl4-openssl-dev libssl-dev
```

Optional but recommended (provides `sigtool` and `freshclam`, avoids CDN
rate limits):

```bash
sudo apt install clamav clamav-freshclam
```

Build:

```bash
make
```

This produces the `viscan` binary in the project root.

---

## Directory Layout

```
.
├── Makefile
├── src/
│   ├── main.c
│   ├── hash_utils.c
│   ├── hdb_parser.c
│   ├── quarantine.c
│   ├── update_database.c
│   ├── ac_engine.c
│   └── h/
│       ├── hash_utils.h
│       ├── hdb_parser.h
│       ├── quarantine.h
│       ├── update_database.h
│       └── ac_engine.h
├── database/           # created automatically
├── quarantine/         # created automatically
└── viscan              # compiled binary
```

`database/` and `quarantine/` are created in the current working
directory, not next to the binary.

---

## Usage

```bash
# Scan files or directories
./viscan [OPTIONS] <file_or_dir1> [file_or_dir2 ...]

# Quarantine vault operations
./viscan --quarantine-list
./viscan --quarantine-restore <id> [--dest <path>]
./viscan --quarantine-clean [--days N]
```

### Scan options

| Option           | Description                                            |
| ---------------- | ------------------------------------------------------ |
| `--verbose`      | Print detailed scanning information                    |
| `--force-update` | Force database refresh, even if it looks fresh         |
| `--pattern-scan` | Enable best-effort pattern matching (see caveats)      |
| `--help`         | Show help                                              |

### Quarantine options

| Option                    | Description                                          |
| ------------------------- | ---------------------------------------------------- |
| `--quarantine-list`       | List all entries in the vault                        |
| `--quarantine-restore ID` | Restore an entry by ID                               |
| `--dest <path>`           | Override restore destination (default: original)     |
| `--quarantine-clean`      | Remove old entries from the vault                    |
| `--days N`                | Age threshold for clean (default 30; 0 removes all)  |

### Examples

```bash
# Standard scan (hash matching only — recommended)
./viscan --verbose ~/Downloads

# Force a database refresh
./viscan --force-update ~/somefile

# Scan with pattern matching enabled (research use only)
./viscan --pattern-scan --verbose /tmp/malware-samples

# Vault operations
./viscan --quarantine-list
./viscan --quarantine-restore 20260913T134453_a443473d
./viscan --quarantine-restore 20260913T134453_a443473d --dest /tmp/recovered.bin
./viscan --quarantine-clean --days 7
./viscan --quarantine-clean --days 0     # wipe the entire vault
```

---

## Signature Formats

| Extension | Description              | Supported?                                  |
| --------- | ------------------------ | ------------------------------------------- |
| `.hdb`    | MD5 signatures           | Yes — always loaded                         |
| `.fp`     | False-positive whitelist | Yes — always loaded                         |
| `.ndb`    | Pattern signatures       | Only with `--pattern-scan`, Target-Type `0` |
| `.ldb`    | Logical signatures       | No — requires expression evaluator          |
| `.mdb`    | Extended pattern rules   | No — same reason as `.ldb`                  |
| other     | `.cdb`, `.crb`, …        | Ignored                                     |

`.ldb` and `.mdb` encode signatures as logical expressions (`&`, `|`, `!`,
parentheses). Evaluating them correctly requires a full expression engine
plus file-type detection. Treating sub-signatures as standalone patterns
produces unacceptable false-positive rates. For `.ldb` / `.mdb` coverage,
use the official `clamscan`.

---

## Pattern Scan Caveats

`--pattern-scan` enables Aho-Corasick matching against `.ndb` signatures.
It is off by default because it is a best-effort matcher and will produce
false positives on untrusted binary files.

Rules applied when the flag is set:

- Only `.ndb` is loaded (not `.ldb` / `.mdb`)
- Only Target-Type `0` ("any") signatures are accepted
- Patterns must be at least 32 bytes long
- At most 200,000 patterns are loaded (RAM guard)

Even with these limits, expect noise. Use `--pattern-scan` only for
research and do not auto-quarantine based on its output.

---

## Quarantine Vault

Files are stored encrypted with AES-256-GCM in `quarantine/`:

```
quarantine/
├── .key                    # 32-byte AES key, mode 0600
├── <id>.enc                # nonce(12) || ciphertext || tag(16)
└── <id>.meta               # plain-text metadata
```

`<id>` is `YYYYMMDDTHHMMSS_xxxxxxxx` (timestamp + 4 random bytes).

### Metadata recorded

- Original absolute path
- MD5 (the hash that triggered detection)
- SHA-256 of the plaintext (verified on restore)
- File size, mode, mtime, uid, gid
- Detection reason and quarantine timestamp

### Guarantees

- Non-destructive store: original is unlinked only after the encrypted
  payload and metadata are fully written and flushed
- Integrity check on restore: GCM tag verification plus SHA-256
  comparison against the recorded digest
- No overwrite on restore
- Restrictive permissions: vault `0700`, key `0600`, entries `0600`

### Limitations

- Vault lives on the same filesystem as the working directory
- Key is protected only by filesystem permissions
- Restore is not atomic; a crash mid-write leaves a partial file at the
  destination, though the vault entry itself remains intact

---

## Database Update Strategy

`update_if_needed()` uses three fallback strategies in order. Only files
that are actually missing or stale are fetched.

1. **Direct download** via libcurl from `database.clamav.net` using a
   user agent matching `freshclam`. Downloads go to `.tmp` files and are
   atomically renamed into place.
2. **`freshclam`** is invoked with `--quiet --datadir database` if the
   direct download fails. Bypasses CDN rate limits.
3. **System ClamAV install**: if `freshclam` is unavailable but
   `/var/lib/clamav/main.cvd` and `daily.cvd` exist, they are copied in.

Extraction uses `sigtool --unpack` if available, otherwise
`tail -c +513 <file> | tar -xzf - -C .`. Extracted files are chmod'ed to
`0644` to avoid umask-induced mode `0000` breakage.

### Rate limits

The ClamAV CDN (behind Cloudflare) enforces strict rate limits on direct
downloads. On `HTTP 429`, either install ClamAV and let `freshclam`
handle it, or wait roughly an hour before retrying.

### Freshness

A database is fresh when:

- Both `main.cvd` and `daily.cvd` (or `.cld` variants) exist
- Both are younger than 6 weeks
- At least one extracted signature file is present and readable

---

## Security Notes

- `system()` is used only for `tail | tar` extraction (fixed arguments,
  no user input) and directory cleanup
- External tools (`sigtool`, `freshclam`) are invoked via `fork` +
  `execlp`, never through a shell
- Symlink traversal during scanning is prevented by `FTW_PHYS`
- Pattern scanning caps file size at 100 MiB
- MD5 lookups use a hash table (FNV-1a, 2^21 buckets)
- No raw file content is retained in memory after a scan

---

## Test File (EICAR)

```bash
echo -n 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > eicar.com
./viscan --verbose ./eicar.com
```

Detection depends on whether the current ClamAV databases include the
EICAR MD5 in `.hdb`, or whether `--pattern-scan` is enabled and the
corresponding `.ndb` entry is loaded.

---

## Exit Codes

| Code | Meaning                                                  |
| ---- | -------------------------------------------------------- |
| `0`  | Scan completed, nothing infected                         |
| `1`  | At least one infected file, or a setup failure occurred  |

---

## Limitations

- No archive scanning (`.zip`, `.tar`, `.rar`, …)
- No PE / OLE2 / PDF parsing — signatures match raw bytes only
- No behavioral analysis — static hash and pattern matching only
- MD5-only for hash matching; `.hsb` / `.msb` SHA databases are ignored

For production-grade protection, use ClamAV itself or a commercial
endpoint security product. ViScan is a small, readable scanner intended
for learning, auditing small collections of files, and integration into
pipelines where ClamAV's dependency footprint is undesirable.

---

## License

GNU General Public License v2.0 (GPLv2). See the `LICENSE` file.
