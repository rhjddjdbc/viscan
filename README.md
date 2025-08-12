# ViScan

ViScan is a lightweight file scanner that detects malware by matching file hashes against known signatures. It uses the ClamAV databases.

## Features

- Recursive scanning of files and directories  
- Uses MD5 hashes for malware detection  
- Supports multiple ClamAV signature database formats:  
  - `.hdb`  
  - `.cdb`  
  - `.ldb`  
  - `.mdb`  
- Automatic quarantine of infected files  
- Verbose mode for detailed output

## Building ViScan

Compile ViScan by running:

```bash
make
````

This will generate the executable `viscan`.

## Databases
https://database.clamav.net/main.cvd
https://database.clamav.net/daily.cvd 

## Using ClamAV Signature Databases

ViScan supports ClamAV databases with extensions `.hdb`, `.cdb`, `.ldb`, and `.mdb`. These files contain malware signatures that ViScan uses for detection.

### Unpacking ClamAV Databases

**The script and databases must be in the same directory as viscan.**
Use the following script to unpack the official `.cvd` database files and move the extracted signature files into the `database/` folder:

```bash
#!/bin/bash
set -e

mkdir -p database

if [[ -f database/daily.cvd ]]; then
    sigtool --unpack database/daily.cvd
else
    echo "Warning: database/daily.cvd not found!"
fi

if [[ -f database/main.cvd ]]; then
    sigtool --unpack database/main.cvd
else
    echo "Warning: database/main.cvd not found!"
fi

for f in *; do
    if [[ -f "$f" && ( "$f" == *.hdb || "$f" == *.cdb || "$f" == *.ldb || "$f" == *.mdb ) ]]; then
        mv "$f" database/
        echo "Moved $f to database/"
    fi
done

echo "Done."
```

### Running the Scanner

After unpacking and placing the database files in `database/`, run ViScan as:

```bash
./viscan [--verbose] <file_or_dir1> [file_or_dir2 ...]
```

Use the `--verbose` option for detailed scanning output.

## Database Location

ViScan expects signature files inside the `database/` directory, including files with the extensions `.hdb`, `.cdb`, `.ldb`, and `.mdb`.

## License

ViScan is licensed under the GNU General Public License version 2 (GPLv2). See the `LICENSE` file for details.
