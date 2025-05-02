#!/bin/bash

# Выход при любой ошибке
set -e

# Очистка старых временных файлов
rm -f js_nuclei.txt

# Запуск getJS для сбора данных
getJS -input alive_http_services.txt -output js.txt -complete -threads 200

# Запуск nuclei параллельно для каждой части
nuclei -l js.txt -tags token,tokens -es unknown -rl 1000 -c 100 -o js_nuclei.txt