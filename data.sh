#!/bin/bash
set -e

mkdir -p database

# Move all main* and daily* files to database/
for f in *; do
    if [[ -f "$f" && ("$f" == *main* || "$f" == *daily*) ]]; then
        mv "$f" database/
        echo "Moved $f to database/"
    fi
done 

cd database

if [[ -f daily.cvd ]]; then
    sigtool --unpack daily.cvd
else
    echo "Warning: database/daily.cvd not found!"
fi

if [[ -f main.cvd ]]; then
    sigtool --unpack main.cvd
else
    echo "Warning: database/main.cvd not found!"
fi

echo "Done."
