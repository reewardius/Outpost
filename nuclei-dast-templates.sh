#!/bin/bash

# Выход при любой ошибке
set -e

# Переменная с именем входного файла
INPUT_FILE="katana.jsonl"

# Проверяем, существует ли файл
if [[ ! -f "$INPUT_FILE" ]]; then
  echo "Файл $INPUT_FILE не найден!"
  exit 1
fi

# Очистка старых временных файлов
rm -f part_* part_*.out nuclei-dast-templates-results.txt

# Разбиваем файл на 3 равные части
split -n l/3 "$INPUT_FILE" part_

# Запуск nuclei параллельно для каждой части
parallel -j 3 "nuclei -l {} -im jsonl -itags blind-xss -t nuclei-dast-templates/ -pc 100 -c 100 -rl 1000 -bs 100 -o {}.out" ::: part_*

# Объединение всех выходных файлов в один
cat part_*.out > nuclei-dast-templates-results.txt

# Удаление временных файлов
rm -f part_* part_*.out

echo "Готово. Результаты сохранены в nuclei-dast-templates-results.txt"