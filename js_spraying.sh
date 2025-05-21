#!/bin/bash
set -e
set -o pipefail


# Determining which Python command to use
if command -v python3 &> /dev/null; then
    PYTHON_CMD="python3"
elif command -v python &> /dev/null; then
    PYTHON_CMD="python"
else
    echo "Python is not installed on the system..."
    exit 1
fi


echo "[*] JS Endpoints Spraying..."

rm -rf finder/
mkdir -p finder/

# Run finder-js.py, but if there is no js.txt, don't break the script
if ! $PYTHON_CMD finder-js.py -l js.txt -o endpoints.txt; then
  echo "Warning: finder-js.py terminated with an error (possibly js.txt is missing). Continued..."
fi

# Check that endpoints.txt has been created and is not empty
if [ ! -s endpoints.txt ]; then
  echo "Error: endpoints.txt is not created or is empty. Skip further steps..."
else
  grep -Ei 'api|v1|v2|v3|user|admin|internal|debug|data|account|config' endpoints.txt > finder/juicyinfo.txt
  grep -E 'http://|https://' endpoints.txt > finder/http_links.txt
  grep -E 'create|add|security|reset| update|delete|modify|remove|list|offer|show|trace|allow|disallow|approve|reject|start|stop|set' endpoints.txt > finder/interested_api_endpoints.txt

  for f in finder/http_links.txt finder/interested_api_endpoints.txt finder/juicyinfo.txt; do
    if [ -s "$f" ]; then
      sort -u "$f" -o "$f"
    else
      echo "Note: file $f is empty or does not exist, skip sorting..."
    fi
  done

  if [ -s finder/juicyinfo.txt ]; then
    sed -i 's|^/||' finder/juicyinfo.txt
  fi
  if [ -s finder/interested_api_endpoints.txt ]; then
    sed -i 's|^/||' finder/interested_api_endpoints.txt
  fi

  if [ -s finder/juicyinfo.txt ]; then
    ffuf -u URL/TOP -w alive_http_services.txt:URL -w finder/juicyinfo.txt:TOP -ac -mc 200 -o fuzz_results.json -fs 0 || echo "FFUF with juicyinfo.txt terminated with an error, but we continue"
    $PYTHON_CMD delete_falsepositives.py -j fuzz_results.json -o fuzz_output3.txt -fp fp_domains3.txt || echo "delete_falsepositives.py (fuzz_output3) error, ignore.."
  else
    echo "The finder/juicyinfo.txt file is missing or empty, skip the first run of ffuf..."
  fi

  if [ -s finder/interested_api_endpoints.txt ]; then
    ffuf -u URL/TOP -w alive_http_services.txt:URL -w finder/interested_api_endpoints.txt:TOP -ac -mc 200 -o fuzz_results.json -fs 0 || echo "FFUF with interested_api_endpoints.txt terminated with an error, but we continue..."
    $PYTHON_CMD delete_falsepositives.py -j fuzz_results.json -o fuzz_output4.txt -fp fp_domains4.txt || echo "delete_falsepositives.py (fuzz_output4) error, ignore..."
  else
    echo "The file finder/interested_api_endpoints.txt is missing or empty, skip the second run of ffuf..."
  fi
fi

# At the end of the script to ensure success
exit 0
