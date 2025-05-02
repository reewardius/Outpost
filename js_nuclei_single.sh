#!/bin/bash

# ����� ��� ����� ������
set -e

# ������� ������ ��������� ������
rm -f js_nuclei.txt

# ������ getJS ��� ����� ������
getJS -input alive_http_services.txt -output js.txt -complete -threads 200

# ������ nuclei ����������� ��� ������ �����
nuclei -l js.txt -tags token,tokens -es unknown -rl 1000 -c 100 -o js_nuclei.txt