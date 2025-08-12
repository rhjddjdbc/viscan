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
    if [[ -f "$f" && ("$f" == *main* || "$f" == *daily*) ]]; then
        mv "$f" database/
        echo "Moved $f to database/"
    fi
done

echo "Done."

