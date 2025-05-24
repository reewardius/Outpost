#!/bin/bash

DEBUG=false
EXPRESS=false
OUTPUT_FILE=""

# Функция для вывода справки
show_help() {
  echo "Usage: bash cookiemonster.sh [OPTIONS]"
  echo
  echo "Options:"
  echo "  -debug              Enable debug mode"
  echo "  -express            Enable express mode"
  echo "  -o, --output FILE   Write successful results to FILE"
  echo "  -help, -h           Show this help message"
  echo
}

# Обработка аргументов
while [[ $# -gt 0 ]]; do
  case "$1" in
    -debug) DEBUG=true; shift ;;
    -express) EXPRESS=true; shift ;;
    -o|--output)
      OUTPUT_FILE="$2"
      if [[ -z "$OUTPUT_FILE" ]]; then
        echo "Error: Missing filename for -o|--output"
        exit 1
      fi
      shift 2
      ;;
    -help|-h) show_help; exit 0 ;;
    *) echo "Unknown option: $1"; show_help; exit 1 ;;
  esac
done

# Очистить файл перед началом, если задан -o
if [[ -n "$OUTPUT_FILE" ]]; then
  > "$OUTPUT_FILE"
fi

# Основной цикл по целям
while IFS= read -r target; do
  echo "[*] Checking: $target"

  unset token
  unset cookie_map

  findings=$(echo "$target" | nuclei -t templates/cookie-extraсtor.yaml -silent)

  if [ -n "$findings" ]; then
    mapfile -t pairs < <(echo "$findings" | grep -oP '[a-zA-Z0-9._-]+=[^;]+' | grep -viE '^(Path|Domain|Expires|HttpOnly|Secure|SameSite|Max-Age)=')

    declare -A cookie_map

    for pair in "${pairs[@]}"; do
      key=$(echo "$pair" | cut -d '=' -f1)
      value=$(echo "$pair" | cut -d '=' -f2-)
      cookie_map["$key"]="$value"
    done

    for key in "${!cookie_map[@]}"; do
      value="${cookie_map[$key]}"

      if $EXPRESS && [[ -n "${cookie_map[$key.sig]}" ]]; then
        value="$value^${cookie_map[$key.sig]}"
        unset cookie_map[$key.sig]
      fi

      if [ -n "$value" ]; then
        if $DEBUG; then
          echo "[DEBUG] Testing cookie: $key=$value"
        fi

        if $EXPRESS; then
          output=$(cookiemonster -cookie "$key=$value")
        else
          output=$(cookiemonster -cookie "$value")
        fi

        if echo "$output" | grep -q "Success" && ! echo "$output" | grep -q "Sorry"; then
          result="[+] Target: $target | Cookie: $key=$value"
          echo "$result"
          echo "$output"

          if [[ -n "$OUTPUT_FILE" ]]; then
            clean_output=$(echo "$output" | sed 's/\x1B\[[0-9;]*[JKmsu]//g')
            {
              echo "$result"
              echo "$clean_output"
              echo "########## RESULT END ##########"
              echo
            } >> "$OUTPUT_FILE"
          fi
        fi
      fi
    done
  fi
  
done < alive_http_services.txt
