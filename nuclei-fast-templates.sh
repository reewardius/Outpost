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
rm -f part_* part_*.out nuclei_fast_templates.txt

# Разбиваем файл на 3 равные части
split -n l/3 "$INPUT_FILE" part_

# Запуск nuclei параллельно для каждой части
parallel -j 3 "nuclei -l {} -etags fuzzing-req,cache,logs,backup,listing,android,ios,ssrf -rl 1000 -c 100 -t nuclei-fast-templates/ -o {}.out" ::: part_*

# Объединение всех выходных файлов в один
cat part_*.out > nuclei_fast_templates.txt

# Удаление временных файлов
rm -f part_* part_*.out

echo "Готово. Результаты сохранены в nuclei_fast_templates.txt"
