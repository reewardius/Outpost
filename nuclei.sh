#!/bin/bash

# Выход при любой ошибке
set -e

rm -f nuclei.txt

nuclei -l alive_http_services.txt -itags config,exposure -etags ssl,tls,headers,waf,dns -eid tech-detect,options-method,blazor-boot,caa-fingerprint -es unknown -rl 1000 -c 100 -o nuclei.txt