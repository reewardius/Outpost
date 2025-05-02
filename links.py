import requests
import os
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor

# Входной файл со списком сайтов
input_file = "alive_http_services.txt"
output_dir = "domains_output"

# Количество потоков
MAX_THREADS = 20

# Создаем папку для сохранения файлов
os.makedirs(output_dir, exist_ok=True)

# Путь к файлу для общего результата
full_output_file = os.path.join(output_dir, "full.txt")

# Функция для извлечения домена
def extract_domain(url):
    parsed = urlparse(url)
    return parsed.netloc if parsed.netloc else None

# Функция проверки доступности (HTTP или HTTPS)
def fetch_site(site_url):
    headers = {"User-Agent": "Mozilla/5.0"}

    parsed = urlparse(site_url)
    
    # Проверяем, доступен ли сайт по указанному протоколу (HTTP или HTTPS)
    try:
        response = requests.get(site_url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.text, parsed.netloc  # Возвращаем HTML + домен
    except requests.RequestException:
        print(f"[-] {site_url} недоступен.")
        return None, None

# Функция парсинга доменов
def get_domains(html):
    domains = set()
    soup = BeautifulSoup(html, "html.parser")

    for tag in soup.find_all(["script", "a", "link", "iframe", "img", "source"]):
        src = tag.get("src") or tag.get("href")
        if src:
            domain = extract_domain(src)
            if domain:
                domains.add(domain)

    return domains

# Функция записи в общий файл
def write_to_full_file(domains):
    with open(full_output_file, "a", encoding="utf-8") as full_file:
        full_file.write("\n".join(sorted(domains)) + "\n")

# Функция обработки одного сайта
def process_site(site):
    print(f"[+] Обрабатываем: {site}")

    # Получаем HTML + домен
    html, site_domain = fetch_site(site)
    if not html or not site_domain:
        return

    # Извлекаем домены
    domains = get_domains(html)

    # Формируем имя файла
    filename = os.path.join(output_dir, f"{site_domain}.txt")

    # Сохраняем домены в отдельный файл для конкретного сайта
    if domains:
        with open(filename, "w", encoding="utf-8") as outfile:
            outfile.write("\n".join(sorted(domains)))
        print(f"    -> Найдено {len(domains)} доменов, сохранено в {filename}.")

        # Записываем домены в общий файл
        write_to_full_file(domains)
    else:
        print("    -> Доменов не найдено.")

# Читаем список сайтов
with open(input_file, "r", encoding="utf-8") as infile:
    sites = [line.strip() for line in infile if line.strip()]

# Запускаем обработку в нескольких потоках
with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
    executor.map(process_site, sites)

print("[✓] Готово!")
