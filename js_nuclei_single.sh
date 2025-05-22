#!/bin/bash

# Выход при любой ошибке
set -e

# Очистка старых временных файлов
rm -f js_nuclei.txt

# Запуск getJS для сбора данных
getJS -input alive_http_services.txt -output js.txt -complete -threads 200

# Проверка существования и непустоты файла js.txt
if [[ ! -s "js.txt" ]]; then
    echo "[!] Файл js.txt не найден или пуст — пропускаем запуск nuclei."
    exit 0
fi

# Запуск nuclei
nuclei -l js.txt -tags token,tokens -es unknown -rl 1000 -c 100 -o nuclei_js.txt
