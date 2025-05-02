#!/bin/bash

# Выход при любой ошибке
set -e

# Переменная с именем входного файла
INPUT_FILE="alive_http_services.txt"

# Проверяем, существует ли файл
if [[ ! -f "$INPUT_FILE" ]]; then
  echo "Файл $INPUT_FILE не найден!"
  exit 1
fi

# Очистка старых временных файлов
rm -f part_* part_*.out nuclei.txt

# Разбиваем файл на 3 равные части
split -n l/3 "$INPUT_FILE" part_

# Запуск nuclei параллельно для каждой части
parallel -j 3 "nuclei -l {} -itags config,exposure -etags ssl,tls,headers,waf,dns -eid tech-detect,options-method,blazor-boot,caa-fingerprint -es unknown -rl 1000 -c 100 -o {}.out" ::: part_*

# Объединение всех выходных файлов в один
cat part_*.out > nuclei.txt

# Удаление временных файлов
rm -f part_* part_*.out