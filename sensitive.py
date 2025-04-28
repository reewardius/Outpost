import re

# Указываем входные и выходные файлы
input_file = "katana.txt"
sensitive_output_file = "sensitive_matches.txt"
juicy_output_file = "juicypath_matches.txt"

# Регулярка для чувствительных файлов
pattern = re.compile(
    r'\b[^/\s]+\.(pem|key|pfx|p12|crt|cer|env|sql|bak|db|sqlite|mdb|ldf|mdf|cfg|config|yml|yaml|json|xml|log|ini|passwd|shadow|htpasswd|pgpass|ovpn|rdp|ps1|sh|bash_history|zsh_history|history|ssh|id_rsa|id_dsa|secrets|cred|credentials|token|backup|dump|dmp|swp|log1|log2|csv|xls|xlsx|tsv|gpg|asc|keystore|jks|pfx|p7b|p7c|crt|csr|der|pkcs12|sso|dat|cache|auth|sess|session|adb|firestore|ndjson|sqlite3|db3|db-wal|db-shm|psql|myd|myi|frm|ibd|parquet|feather|orc|avro|tar|gz|zip|rar|7z|tgz|pdf|bz2|xz|zst|bak1|bak2|old1|old2|log1|log2|xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|git|zip|tar\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|exe|dll|bin|ini|bat|sh|tar|deb|rpm|iso|img|env|apk|msi|dmg|tmp|crt|pem|key|pub|asc)\b',
    re.IGNORECASE
)

# Регулярка для интересных путей (включая JS и CSS файлы, исключаем их позже)
juicy_pattern = re.compile(r'\b(admin|dashboard|register|user|panel|control|debug|console|config|setup|manage)\b', re.IGNORECASE)

# Читаем файл и ищем совпадения
matches = []
juicy_matches = []
with open(input_file, "r", encoding="utf-8") as infile:
    for line in infile:
        # Проверяем на чувствительные файлы
        if pattern.search(line):
            matches.append(line.strip())
        
        # Проверяем на интересные пути в URL, исключаем JS и CSS файлы
        if juicy_pattern.search(line) and not re.search(r'\.(js|css)(\?|$)', line):  # Проверка на файлы .js и .css
            juicy_matches.append(line.strip())  # Добавляем путь в список

# Сохраняем чувствительные файлы в отдельный файл
with open(sensitive_output_file, "w", encoding="utf-8") as sensitive_outfile:
    sensitive_outfile.write("\n".join(matches) + "\n")

# Сохраняем интересные пути в отдельный файл
with open(juicy_output_file, "w", encoding="utf-8") as juicy_outfile:
    for juicy_path in juicy_matches:
        juicy_outfile.write(juicy_path + "\n")  # Каждую juicy path записываем с новой строки

print(f"[+] Найдено {len(matches)} чувствительных файлов. Результаты сохранены в {sensitive_output_file}")
print(f"[+] Найдено {len(juicy_matches)} интересных путей. Результаты сохранены в {juicy_output_file}")
