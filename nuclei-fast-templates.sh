#!/bin/bash

# ����� ��� ����� ������
set -e

# ���������� � ������ �������� �����
INPUT_FILE="alive_http_services.txt"

# ���������, ���������� �� ����
if [[ ! -f "$INPUT_FILE" ]]; then
  echo "���� $INPUT_FILE �� ������!"
  exit 1
fi

# ������� ������ ��������� ������
rm -f part_* part_*.out nuclei_fast_templates.txt

# ��������� ���� �� 3 ������ �����
split -n l/3 "$INPUT_FILE" part_

# ������ nuclei ����������� ��� ������ �����
parallel -j 3 "nuclei -l {} -etags fuzzing-req,cache,logs,backup,listing,android,ios,ssrf -rl 1000 -c 100 -t nuclei-fast-templates/ -o {}.out" ::: part_*

# ����������� ���� �������� ������ � ����
cat part_*.out > nuclei_fast_templates.txt

# �������� ��������� ������
rm -f part_* part_*.out

echo "������. ���������� ��������� � nuclei_fast_templates.txt"
