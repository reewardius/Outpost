#!/bin/bash
set -e
set -o pipefail

# Checking arguments
if [[ "$1" == "-f" && -n "$2" ]]; then
    echo "[*] Using domain list from file: $2"
    DOMAIN_MODE="file"
    TARGET_FILE="$2"
    ROOT_INPUT="$TARGET_FILE"
    
    if [[ "$3" == "-ds" ]]; then
        # Skip subfinder and transfer domains directly to naabu
        echo "[*] Skipping Subfinder, passing domains directly to naabu"
        RUN_SUBFINDER=false
        NAABU_CMD="naabu -l $TARGET_FILE -s s -tp 100 -ec -c 50 -o naabu.txt"
    else
        RUN_SUBFINDER=true
        SUBFINDER_CMD="subfinder -dL $TARGET_FILE -all -silent -o subs.txt"
        NAABU_CMD="naabu -l subs.txt -s s -tp 100 -ec -c 50 -o naabu.txt"
    fi
elif [[ "$1" == "-d" && -n "$2" ]]; then
    RAW_DOMAIN="$2"
    TARGET_DOMAIN=$(echo "$RAW_DOMAIN" | sed -E 's|https?://||' | cut -d/ -f1)

    if [[ -z "$TARGET_DOMAIN" ]]; then
        echo "[-] Invalid domain specified. Provide domain without protocol, e.g., example.com"
        exit 1
    fi

    echo "[*] Using single domain: $TARGET_DOMAIN"
    DOMAIN_MODE="single"
    ROOT_INPUT="$TARGET_DOMAIN"

    if [[ "$3" == "-ds" ]]; then
        # Skip subfinder and transfer the domain to naabu
        echo "[*] Skipping Subfinder, passing directly to naabu"
        RUN_SUBFINDER=false
        NAABU_CMD="naabu -host $TARGET_DOMAIN -s s -tp 100 -ec -c 50 -o naabu.txt"
    else
        RUN_SUBFINDER=true
        SUBFINDER_CMD="subfinder -d $TARGET_DOMAIN -all -silent -o subs.txt"
        NAABU_CMD="naabu -l subs.txt -s s -tp 100 -ec -c 50 -o naabu.txt"
    fi
else
    echo "Usage: $0 [-f file.txt | -d target.com] [-ds (optional)]"
    exit 1
fi

# Clearing previous results
rm -f subs.txt naabu.txt alive_http_services.txt fuzz_results.json fuzz_output.txt fp_domains_alive.txt tech-detect.txt nuclei_config_exposures.txt passive.txt katana_uniq.txt katana.txt sensitive_matches.txt sensitive.txt js.txt juicypath_matches.txt juicypath.txt second_order_takeover.txt js_nuclei.txt nuclei.txt nuclei-dast-fast-templates-results.txt general.txt katana.jsonl nuclei-dast-templates-results.txt nuclei_fast_templates.txt s3scanner.txt part_* part_*.out op.txt fuzz_output*.txt paths.txt fp_domains*.txt new_paths.txt swagger_get_200.txt third_order_takeover.txt nuclei-dast-hidden-params-results.txt endpoints.txt

echo "[*] Starting Recon..."
if [ "$RUN_SUBFINDER" = true ]; then
    eval $SUBFINDER_CMD
fi
eval $NAABU_CMD

# Httpx launching
httpx -l naabu.txt -rl 500 -t 200 -o alive_http_services.txt && httpx -l naabu.txt -rl 500 -t 200 -td -sc -o tech-detect.txt

# S3 Scanner
echo "[*] Starting S3Scanner..."
s3scanner -bucket-file naabu.txt -provider aws -threads 16 | grep exists > s3scanner.txt || true

# Run Ffuf
echo "[*] Starting Web Fuzzing..."
ffuf -u URL/TOP -w alive_http_services.txt:URL -w top.txt:TOP -t 1000 -ac -mc 200 -o fuzz_results.json -fs 0
python3 delete_falsepositives.py -j fuzz_results.json -o fuzz_output1.txt -fp fp_domains1.txt
httpx -l fp_domains1.txt -rl 500 -t 200 -o fp_domains_alive.txt
nuclei -l fp_domains_alive.txt -tags config,exposure -es unknown -c 100 -rl 1000 -o nuclei_config_exposures.txt

# Katana Active Crawl (results in JSONL)
echo "[*] Starting Active Crawling..."
katana -u alive_http_services.txt -d 5 -ef js,json,png,css,jpg,jpeg,woff2,svg -c 150 -p 150 -rl 1000 -ct 5m -aff -iqp -headless -nos -j -o katana.jsonl

# Katana Passive Wayback Archive
echo "[*] Katana Passive Crawl from Wayback Archive..."
katana -u "$ROOT_INPUT" -ps -f qurl -o passive.txt
uro -i passive.txt -o katana_uniq.txt

# Collecting Sensitive Data from Wayback Archive
echo "[*] Collecting Sensitive Data from Wayback Archive..."
katana -u "$ROOT_INPUT" -ps -o katana.txt
python3 sensitive.py
httpx -l sensitive_matches.txt -mc 200 -o sensitive.txt
httpx -l juicypath_matches.txt -mc 200 -o juicy_temp.txt && uro -i juicy_temp.txt -o juicypath.txt && rm -f juicy_temp.txt

# Fuzzing Multiple Paths from Wayback Archive
echo "[*] Starting Fuzzing Multiple Paths from Wayback Archive..."
uro -i katana.txt -o op.txt
cat op.txt | unfurl format %p | anew paths.txt > /dev/null 2>&1 && sed 's|^/||' paths.txt > new_paths.txt
rm -f fuzz_results.json && ffuf -u URL/TOP -w alive_http_services.txt:URL -w new_paths.txt:TOP -t 1000 -ac -mc 200 -o fuzz_results.json -fs 0
python3 delete_falsepositives.py -j fuzz_results.json -o fuzz_output2.txt -fp fp_domains2.txt

# JS Endpoints Spraying
echo "[*] JS Endpoints Spraying..."
chmod +x js_spraying.sh && bash js_spraying.sh

# Second-Order Hijacking
echo "[*] Starting Second-Order Hijacking..."
rm -f domains_output/*.txt && python3 links.py

if [ -f domains_output/full.txt ]; then
    nuclei -l domains_output/full.txt -profile subdomain-takeovers -nh -rl 500 -o second_order_takeover.txt
else
    echo "[-] File domains_output/full.txt not found, skipping Second-Order Hijacking scan."
fi


# Third-Order Hijacking
echo "[*] Starting Third-Order Hijacking..."
if [ -f finder/http_links.txt ]; then
    nuclei -l finder/http_links.txt -profile subdomain-takeovers -nh -rl 500 -o third_order_takeover.txt
else
    echo "[-] File finder/http_links.txt not found, skipping Third-Order Hijacking scan."
fi


# Nuclei Default Scanning
echo "[*] Nuclei Default Scanning..."
if [[ "$1" == "-f" ]]; then
    chmod +x nuclei_parallel.sh && bash nuclei_parallel.sh
elif [[ "$1" == "-d" ]]; then
    chmod +x nuclei.sh && bash nuclei.sh
fi

# Logic of running custom templates and JS templates
if [[ "$1" == "-f" ]]; then
    echo "[*] Nuclei Custom Fast Templates Scanning..."
    chmod +x nuclei-fast-templates.sh && bash nuclei-fast-templates.sh

    echo "[*] Nuclei JS Secrets Scanning..."
    chmod +x js_nuclei.sh && bash js_nuclei.sh
elif [[ "$1" == "-d" ]]; then
    echo "[*] Nuclei Custom Fast Templates Single Domain Scanning..."
    chmod +x nuclei-fast-templates-single.sh && bash nuclei-fast-templates-single.sh

    echo "[*] Nuclei JS Secrets Scanning..."
    chmod +x js_nuclei_single.sh && bash js_nuclei_single.sh
fi

# Swagger Scanning
echo "[*] Swagger Scanning..."
if [ -f alive_http_services.txt ]; then
    nuclei -l alive_http_services.txt -tags swagger,openapi -o swagger_endpoints.txt
    if [ -f swagger_endpoints.txt ]; then
        python3 swagger_check.py
    else
        echo "[-] File swagger_endpoints.txt not found, skipping swagger_check.py."
    fi
else
    echo "[-] File alive_http_services.txt not found, skipping Swagger Scanning."
fi
# All working GET endpoints (status code 200) are saved in swagger_get_200.txt.

# Merge Ffuf and Swagger Results into one file
echo "[*] Merge Ffuf Results into one file..."
cat fuzz_output1.txt fuzz_output2.txt fuzz_output3.txt fuzz_output4.txt swagger_get_200.txt 2>/dev/null | sort -u > fuzz_output.txt || true

# Nuclei Passive DAST Scanning
echo "[*] Nuclei Passive DAST Scanning..."
chmod +x nuclei-dast-fast-templates.sh && bash nuclei-dast-fast-templates.sh

# Nuclei Active DAST Scanning
echo "[*] Nuclei Active DAST Scanning..."
if [ -f katana.jsonl ]; then
    nuclei -l katana.jsonl -im jsonl -itags blind-xss -t nuclei-dast-templates/ -pc 100 -c 100 -rl 1000 -bs 100 -o nuclei-dast-templates-results.txt
else
    echo "[-] File katana.jsonl not found, skipping nuclei scan."
fi


# Nuclei Active DAST Scanning Hidden Parameters
echo "[*] Nuclei Active DAST Scanning Hidden Parameters..."
python3 hidden-param-extractor.py

if [ -f katana_hidden_params_fuzzing.txt ]; then
    uro -i katana_hidden_params_fuzzing.txt -o katana_urls_with_hidden_params.txt
else
    echo "[-] File katana_hidden_params_fuzzing.txt not found, skipping uro command."
fi

if [ -f katana_urls_with_hidden_params.txt ]; then
    nuclei -l katana_urls_with_hidden_params.txt -t nuclei-dast-templates/ -dast -etags fuzzing-req-header,fuzzing-req-cookie -pc 100 -c 100 -rl 1000 -bs 100 -o nuclei-dast-hidden-params-results.txt
else
    echo "[-] File katana_urls_with_hidden_params.txt not found, skipping nuclei scan."
fi


# Merging Results and Generating Final Report
echo "[*] Merging Results and Generating Final Report..."
cat js_nuclei.txt nuclei.txt nuclei-dast-fast-templates-results.txt nuclei_fast_templates.txt second_order_takeover.txt third_order_takeover.txt nuclei_config_exposures.txt nuclei-dast-templates-results.txt nuclei-dast-hidden-params-results.txt 2>/dev/null | sort -u > general.txt && python3 modern_report.py general.txt

# Generating an overall modern report
echo "[*] General Nuclei Report Generated -> Open general_report.html"
