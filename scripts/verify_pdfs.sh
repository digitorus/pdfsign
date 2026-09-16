#!/bin/bash
set -e

# verify_pdfs.sh
# Validates all PDF files in the specified directory (default: testfiles/success) using pdfcpu.

DIR="${1:-testfiles/success}"

if ! command -v pdfcpu &> /dev/null; then
    echo "pdfcpu could not be found. Please install it to use this script."
    exit 1
fi

if [ ! -d "$DIR" ]; then
    echo "Directory $DIR does not exist."
    exit 1
fi

echo "Validating PDFs in $DIR..."
count=0
fail=0

for pdf in "$DIR"/*.pdf; do
    [ -e "$pdf" ] || continue

    filename=$(basename "$pdf")

    # Skip files that are expected to fail
    if [[ "$filename" == *"FormFillAPI.pdf" ]]; then
        echo "Skipping $filename (Expected Failure for API Test)"
        continue
    fi

    echo -n "Checking $filename... "
    if pdfcpu validate -m strict "$pdf" > /dev/null 2>&1; then
        echo "OK (Strict)"
    else
        if pdfcpu validate -m relaxed "$pdf" > /dev/null 2>&1; then
            echo "OK (Relaxed - Input likely had issues)"
        else
            echo "FAIL"
            fail=$((fail + 1))
        fi
    fi
    count=$((count + 1))
done

echo "------------------------------------------------"
echo "Scanned $count files."
if [ $fail -eq 0 ]; then
    echo "All files passed validation."
    exit 0
else
    echo "$fail files FAILED validation."
    exit 1
fi
