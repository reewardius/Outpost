import json
import re
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# === Настройки ===
KATANA_FILE = "katana.jsonl"
OUTPUT_FILE = "katana_hidden_params_fuzzing.txt"
THREADS = 10

# === Заголовки для запроса ===
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (compatible; hidden-finder/1.0)'
}

# === Регулярка для hidden input'ов ===
RE_HIDDEN = re.compile(
    r'<input[^>]+type=["\']?hidden["\']?[^>]*name=["\']?([^"\'>\s]+)["\']?', re.I)

# === Извлекаем endpoint'ы из katana.jsonl ===
def extract_endpoints(katana_file):
    endpoints = set()
    with open(katana_file, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                obj = json.loads(line)
                endpoint = obj.get("request", {}).get("endpoint")
                if endpoint:
                    endpoints.add(endpoint)
            except json.JSONDecodeError:
                continue
    print(f"[+] Найдено {len(endpoints)} уникальных endpoint'ов.")
    return sorted(endpoints)

# === Получаем страницу и парсим hidden параметры ===
def fetch_hidden_params(url):
    try:
        resp = requests.get(url, headers=HEADERS, timeout=5, verify=False)
        if resp.status_code != 200:
            return None
        html = resp.text
        params = [f"{name}=enumrust" for name in RE_HIDDEN.findall(html) if "__" not in name]
        if not params:
            return None
        sep = '&' if '?' in url else '?'
        return f"{url}{sep}{'&'.join(params)}"
    except Exception:
        return None

# === Основная логика ===
def main():
    print(f"[*] Чтение Katana JSONL из {KATANA_FILE}...")
    endpoints = extract_endpoints(KATANA_FILE)

    print(f"[*] Поиск скрытых параметров (в потоках: {THREADS})...")
    results = []
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        future_to_url = {executor.submit(fetch_hidden_params, url): url for url in endpoints}
        for future in as_completed(future_to_url):
            result = future.result()
            if result:
                results.append(result)

    with open(OUTPUT_FILE, 'w') as f:
        for url in results:
            f.write(url + '\n')

    print(f"[+] Готово! Найдено {len(results)} URL с hidden-параметрами. Сохранено в {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
