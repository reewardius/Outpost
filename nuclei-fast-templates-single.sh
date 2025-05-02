#!/bin/bash

# Выход при любой ошибке
set -e

nuclei -l alive_http_services.txt -eid web-cache-poisoning,cache-poisoning-fuzz -etags fuzzing-req,logs,backup,listing,android,ios,ssrf -rl 1000 -c 100 -t nuclei-fast-templates/ -o nuclei_fast_templates.txt
