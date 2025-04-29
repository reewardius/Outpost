import re
import sys
import os
import html
from collections import defaultdict
from datetime import datetime

def parse_vulnerabilities(text):
    # Регулярное выражение для извлечения основных данных
    pattern = r'\[(.*?)\] \[(.*?)\] \[(.*?)\] (.*?)(?=$)'
    
    vulns = []
    
    for match in re.finditer(pattern, text, re.MULTILINE):
        cve_or_type, protocol, severity, remaining_text = match.groups()
        
        # Извлекаем URL и дополнительные данные
        url = remaining_text.strip()
        extractors = []
        
        # Ищем квадратные скобки в конце (extractors)
        brackets_match = re.search(r'(.*?)(\s+\[.*?\]\s*)$', url)
        if brackets_match:
            url = brackets_match.group(1).strip()
            # Извлекаем все данные в квадратных скобках
            extractor_text = brackets_match.group(2).strip()
            # Используем отдельное регулярное выражение для выделения текста в квадратных скобках
            extractor_matches = re.findall(r'\[(.*?)\]', extractor_text)
            for ext in extractor_matches:
                extractors.append(ext)
        
        vulns.append({
            "cve_or_type": cve_or_type.strip(),
            "protocol": protocol.strip(),
            "severity": severity.strip(),
            "url": url,
            "extractors": extractors
        })
    
    return vulns

def parse_url_list_file(file_path):
    """Парсит файл с URL-ами, по одному на строку"""
    results = []
    
    if not os.path.exists(file_path):
        print(f"Предупреждение: Файл '{file_path}' не найден.")
        return results
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                url = line.strip()
                if url and url.startswith(('http://', 'https://')):
                    results.append(url)
    except Exception as e:
        print(f"Ошибка при чтении файла {file_path}: {e}")
    
    return results

def parse_s3scanner_file(file_path):
    """Парсит файл с результатами S3Scanner"""
    results = []
    
    if not os.path.exists(file_path):
        print(f"Предупреждение: Файл '{file_path}' не найден.")
        return results
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
            # Регулярное выражение для извлечения данных из строк S3Scanner
            pattern = r'level=info msg="exists\s+\|\s+(.*?)\s+\|\s+(.*?)\s+\|\s+AuthUsers:\s+(.*?)\s+\|\s+AllUsers:\s+(.*?)"'
            
            for match in re.finditer(pattern, content):
                bucket_name, region, auth_users, all_users = match.groups()
                
                results.append({
                    "bucket_name": bucket_name.strip(),
                    "region": region.strip(),
                    "auth_users": auth_users.strip(),
                    "all_users": all_users.strip()
                })
                
    except Exception as e:
        print(f"Ошибка при чтении файла {file_path}: {e}")
    
    return results

def generate_html_report(vulnerabilities, input_filename, additional_files=None):
    if additional_files is None:
        additional_files = {}
    
    # Группировка уязвимостей по критичности
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    vuln_by_severity = defaultdict(list)
    
    for vuln in vulnerabilities:
        severity = vuln["severity"].lower()
        vuln_by_severity[severity].append(vuln)
    
    # HTML шаблон
    report_title = os.path.splitext(os.path.basename(input_filename))[0]
    html_output = f"""<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Отчет по уязвимостям: {html.escape(report_title)}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: #fff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }}
        h2 {{
            margin-top: 30px;
            padding: 8px 15px;
            border-radius: 4px;
            color: white;
        }}
        .critical h2 {{ background-color: #e74c3c; }}
        .high h2 {{ background-color: #e67e22; }}
        .medium h2 {{ background-color: #f39c12; }}
        .low h2 {{ background-color: #2ecc71; }}
        .info h2 {{ background-color: #3498db; }}
        .unknown h2 {{ background-color: #95a5a6; }}
        .ffuf h2 {{ background-color: #9b59b6; }}
        .sensitive h2 {{ background-color: #8e44ad; }}
        .juicypath h2 {{ background-color: #16a085; }}
        .s3scanner h2 {{ background-color: #27ae60; }}
        
        .vuln-table {{
            width: 100%;
            border-collapse: separate; /* Изменено для лучшей совместимости с прокруткой */
            border-spacing: 0;
            margin-bottom: 30px;
            table-layout: fixed; /* Фиксированный макет таблицы */
        }}
        .vuln-table th, .vuln-table td {{
            border: 1px solid #ddd;
            padding: 10px;
            text-align: left;
            vertical-align: top;
            overflow-wrap: break-word; /* Перенос длинных слов */
        }}
        .vuln-table th {{
            background-color: #f2f2f2;
        }}
        .vuln-table tr:nth-child(even) {{
            background-color: #f9f9f9;
        }}
        /* Ширина колонок в процентах */
        .vuln-table th:nth-child(1), .vuln-table td:nth-child(1) {{ width: 20%; }}
        .vuln-table th:nth-child(2), .vuln-table td:nth-child(2) {{ width: 10%; }}
        .vuln-table th:nth-child(3), .vuln-table td:nth-child(3) {{ width: 45%; }}
        .vuln-table th:nth-child(4), .vuln-table td:nth-child(4) {{ 
            width: 25%; 
            position: relative;
            height: 100%;
            padding: 0; /* Убираем отступы, чтобы скролл-контейнер занимал всю ячейку */
        }}
        
        /* Для таблиц с двумя колонками (URL-результаты) */
        .two-col-table th:nth-child(1), .two-col-table td:nth-child(1) {{ width: 10%; }}
        .two-col-table th:nth-child(2), .two-col-table td:nth-child(2) {{ width: 90%; }}
        
        /* Для таблицы S3Scanner */
        .s3scanner-table th:nth-child(1), .s3scanner-table td:nth-child(1) {{ width: 5%; }}
        .s3scanner-table th:nth-child(2), .s3scanner-table td:nth-child(2) {{ width: 30%; }}
        .s3scanner-table th:nth-child(3), .s3scanner-table td:nth-child(3) {{ width: 20%; }}
        .s3scanner-table th:nth-child(4), .s3scanner-table td:nth-child(4) {{ width: 20%; }}
        .s3scanner-table th:nth-child(5), .s3scanner-table td:nth-child(5) {{ width: 25%; }}
        
        .vuln-url {{
            word-break: break-all;
        }}
        .extractor {{
            display: inline-block;
            background-color: #f1f1f1;
            padding: 2px 5px;
            margin: 2px;
            border-radius: 3px;
            font-size: 0.85em;
            font-family: monospace;
            border: 1px solid #ddd;
        }}
        /* Обновленные стили для контейнера с прокруткой */
        .scroll-container {{
            max-height: 150px;
            overflow-y: auto;
            border: 1px solid #eee;
            padding: 10px;
            background-color: #fafafa;
            display: block;
            width: 100%;
            height: 100%;
            box-sizing: border-box;
            border-radius: 3px;
        }}
        .extractors-cell {{
            padding: 5px;
            margin: 0;
        }}
        .summary {{
            margin-bottom: 20px;
            padding: 15px;
            background-color: #edf2f7;
            border-radius: 4px;
        }}
        .summary-table {{
            width: 300px;
            border-collapse: collapse;
            margin-top: 10px;
        }}
        .summary-table td {{
            padding: 5px 10px;
            border: 1px solid #ddd;
        }}
        .summary-table td:first-child {{
            font-weight: bold;
        }}
        footer {{
            margin-top: 30px;
            text-align: center;
            font-size: 0.8em;
            color: #7f8c8d;
        }}
        .source-file {{
            font-style: italic;
            color: #7f8c8d;
            margin-bottom: 20px;
        }}
        .no-vulns {{
            padding: 15px;
            background-color: #f8d7da;
            color: #721c24;
            border-radius: 4px;
            margin: 20px 0;
        }}
        .severity-badge {{
            display: inline-block;
            padding: 3px 6px;
            border-radius: 3px;
            color: white;
            font-size: 0.8em;
            margin-right: 5px;
        }}
        .badge-critical {{ background-color: #e74c3c; }}
        .badge-high {{ background-color: #e67e22; }}
        .badge-medium {{ background-color: #f39c12; }}
        .badge-low {{ background-color: #2ecc71; }}
        .badge-info {{ background-color: #3498db; }}
        .badge-unknown {{ background-color: #95a5a6; }}
        .tooltip {{
            position: relative;
            display: inline-block;
            cursor: help;
        }}
        .tooltip .tooltiptext {{
            visibility: hidden;
            width: 200px;
            background-color: #555;
            color: #fff;
            text-align: center;
            border-radius: 6px;
            padding: 5px;
            position: absolute;
            z-index: 1;
            bottom: 125%;
            left: 50%;
            margin-left: -100px;
            opacity: 0;
            transition: opacity 0.3s;
        }}
        .tooltip:hover .tooltiptext {{
            visibility: visible;
            opacity: 1;
        }}
        .tab {{
            overflow: hidden;
            border: 1px solid #ccc;
            background-color: #f1f1f1;
            border-radius: 5px 5px 0 0;
        }}
        .tab button {{
            background-color: inherit;
            float: left;
            border: none;
            outline: none;
            cursor: pointer;
            padding: 14px 16px;
            transition: 0.3s;
            font-size: 17px;
        }}
        .tab button:hover {{
            background-color: #ddd;
        }}
        .tab button.active {{
            background-color: #3498db;
            color: white;
        }}
        .tabcontent {{
            display: none;
            padding: 20px;
            border: 1px solid #ccc;
            border-top: none;
            border-radius: 0 0 5px 5px;
            animation: fadeEffect 1s;
        }}
        @keyframes fadeEffect {{
            from {{opacity: 0;}}
            to {{opacity: 1;}}
        }}
        .highlight-row {{
            background-color: #ffe0b2 !important;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Отчет по уязвимостям</h1>
        <div class="source-file">Исходный файл: {html.escape(input_filename)}</div>
        
        <div class="summary">
            <h3>Сводная информация</h3>
            <table class="summary-table">
                <tr>
                    <td>Critical</td>
                    <td>{len(vuln_by_severity.get("critical", []))}</td>
                </tr>
                <tr>
                    <td>High</td>
                    <td>{len(vuln_by_severity.get("high", []))}</td>
                </tr>
                <tr>
                    <td>Medium</td>
                    <td>{len(vuln_by_severity.get("medium", []))}</td>
                </tr>
                <tr>
                    <td>Low</td>
                    <td>{len(vuln_by_severity.get("low", []))}</td>
                </tr>
                <tr>
                    <td>Info</td>
                    <td>{len(vuln_by_severity.get("info", []))}</td>
                </tr>
                <tr>
                    <td>Unknown</td>
                    <td>{len(vuln_by_severity.get("unknown", []))}</td>
                </tr>
                <tr>
                    <td>Всего</td>
                    <td>{len(vulnerabilities)}</td>
                </tr>
"""

    # Добавляем информацию о дополнительных файлах в таблицу
    for file_type, file_data in additional_files.items():
        if file_data and len(file_data) > 0:
            file_name = {"ffuf": "Ffuf находки", 
                         "sensitive": "Sensitive находки", 
                         "juicypath": "JuicyPath находки",
                         "s3scanner": "S3Scanner находки"}.get(file_type, file_type)
            html_output += f"""
                <tr>
                    <td>{file_name}</td>
                    <td>{len(file_data)}</td>
                </tr>
"""

    html_output += """
            </table>
        </div>
        
        <div class="tab">
            <button class="tablinks active" onclick="openTab(event, 'NucleiTab')">Nuclei</button>
"""

    # Добавляем вкладки для дополнительных файлов, если они есть
    for file_type, file_data in additional_files.items():
        if file_data and len(file_data) > 0:
            tab_name = {"ffuf": "Ffuf", 
                        "sensitive": "Sensitive", 
                        "juicypath": "JuicyPath",
                        "s3scanner": "S3Scanner"}.get(file_type, file_type.capitalize())
            html_output += f"""
            <button class="tablinks" onclick="openTab(event, '{file_type.capitalize()}Tab')">{tab_name}</button>
"""

    html_output += """
        </div>
        
        <div id="NucleiTab" class="tabcontent" style="display: block;">
"""

    if not vulnerabilities:
        html_output += """
            <div class="no-vulns">
                <p>В отчете не найдено уязвимостей. Проверьте формат входного файла.</p>
            </div>
        """
    else:
        # Добавляем секции по уровням критичности в нужном порядке
        for severity_name in sorted(vuln_by_severity.keys(), key=lambda x: severity_order.get(x, 999)):
            vulns = vuln_by_severity[severity_name]
            if not vulns:
                continue
                
            severity_display = severity_name.upper()
            html_output += f"""
                <div class="{severity_name}">
                    <h2>{severity_display} ({len(vulns)})</h2>
                    <table class="vuln-table">
                        <thead>
                            <tr>
                                <th>CVE/Тип</th>
                                <th>Протокол</th>
                                <th>URL</th>
                                <th>Дополнительная информация</th>
                            </tr>
                        </thead>
                        <tbody>
"""
            for vuln in vulns:
                # Экранируем значения для безопасной вставки в HTML
                cve_escaped = html.escape(vuln["cve_or_type"])
                protocol_escaped = html.escape(vuln["protocol"])
                url_escaped = html.escape(vuln["url"])
                
                # Формируем ячейку с extractors в новом формате с гарантированной прокруткой
                extractors_html = ""
                if vuln["extractors"]:
                    extractors_html = '<div class="scroll-container"><div class="extractors-cell">'
                    for extractor in vuln["extractors"]:
                        extractors_html += f'<span class="extractor">{html.escape(extractor)}</span> '
                    extractors_html += '</div></div>'
                else:
                    # Даже если экстракторов нет, создаем пустой скролл-контейнер для единообразия
                    extractors_html = '<div class="scroll-container"><div class="extractors-cell">-</div></div>'
                
                html_output += f"""
                            <tr>
                                <td>{cve_escaped}</td>
                                <td>{protocol_escaped}</td>
                                <td class="vuln-url"><a href="{url_escaped}" target="_blank">{url_escaped}</a></td>
                                <td>{extractors_html}</td>
                            </tr>
"""

            html_output += """
                        </tbody>
                    </table>
                </div>
"""

    html_output += """
        </div>
"""

    # Добавляем содержимое вкладок для дополнительных файлов
    for file_type, file_data in additional_files.items():
        if file_data and len(file_data) > 0:
            tab_name = file_type.capitalize()
            tab_title = {"ffuf": "FFUF РЕЗУЛЬТАТЫ", 
                         "sensitive": "SENSITIVE РЕЗУЛЬТАТЫ", 
                         "juicypath": "JUICYPATH РЕЗУЛЬТАТЫ",
                         "s3scanner": "S3SCANNER РЕЗУЛЬТАТЫ"}.get(file_type, f"{file_type.upper()} РЕЗУЛЬТАТЫ")
            
            if file_type == "s3scanner":
                # Специальный шаблон для S3Scanner
                html_output += f"""
        <div id="{tab_name}Tab" class="tabcontent">
            <div class="{file_type}">
                <h2>{tab_title}</h2>
                <table class="vuln-table s3scanner-table">
                    <thead>
                        <tr>
                            <th>№</th>
                            <th>Имя бакета</th>
                            <th>Регион</th>
                            <th>AuthUsers</th>
                            <th>AllUsers</th>
                        </tr>
                    </thead>
                    <tbody>
"""
                for i, bucket_data in enumerate(file_data, 1):
                    bucket_name = html.escape(bucket_data["bucket_name"])
                    region = html.escape(bucket_data["region"])
                    auth_users = html.escape(bucket_data["auth_users"])
                    all_users = html.escape(bucket_data["all_users"])
                    
                    # Выделяем строки с правами доступа READ для AllUsers
                    row_class = ""
                    if "READ" in all_users:
                        row_class = "highlight-row"
                    
                    html_output += f"""
                        <tr class="{row_class}">
                            <td>{i}</td>
                            <td>{bucket_name}</td>
                            <td>{region}</td>
                            <td>{auth_users}</td>
                            <td>{all_users}</td>
                        </tr>
"""
            else:
                # Стандартный шаблон для остальных файлов
                html_output += f"""
        <div id="{tab_name}Tab" class="tabcontent">
            <div class="{file_type}">
                <h2>{tab_title}</h2>
                <table class="vuln-table two-col-table">
                    <thead>
                        <tr>
                            <th>№</th>
                            <th>URL</th>
                        </tr>
                    </thead>
                    <tbody>
"""
                for i, url in enumerate(file_data, 1):
                    url_escaped = html.escape(url)
                    html_output += f"""
                        <tr>
                            <td>{i}</td>
                            <td class="vuln-url"><a href="{url_escaped}" target="_blank">{url_escaped}</a></td>
                        </tr>
"""

            html_output += """
                    </tbody>
                </table>
            </div>
        </div>
"""

    # JavaScript для вкладок и инициализации скроллов
    html_output += """
        <script>
        function openTab(evt, tabName) {
            var i, tabcontent, tablinks;
            tabcontent = document.getElementsByClassName("tabcontent");
            for (i = 0; i < tabcontent.length; i++) {
                tabcontent[i].style.display = "none";
            }
            tablinks = document.getElementsByClassName("tablinks");
            for (i = 0; i < tablinks.length; i++) {
                tablinks[i].className = tablinks[i].className.replace(" active", "");
            }
            document.getElementById(tabName).style.display = "block";
            evt.currentTarget.className += " active";
        }
        
        // Проверка состояния прокрутки для всех контейнеров при загрузке
        document.addEventListener('DOMContentLoaded', function() {
            var scrollContainers = document.querySelectorAll('.scroll-container');
            scrollContainers.forEach(function(container) {
                // Проверяем, нужен ли скролл
                if (container.scrollHeight > container.clientHeight) {
                    container.style.borderColor = '#ccc';
                } else {
                    container.style.borderColor = '#f0f0f0';
                }
            });
        });
        </script>
"""

    # Завершаем HTML
    current_date = datetime.now().strftime("%d.%m.%Y %H:%M")
    html_output += f"""
        <footer>
            Отчет сгенерирован: {current_date}
        </footer>
    </div>
</body>
</html>
"""
    return html_output

def main():
    # Проверяем, что файл указан в аргументах
    if len(sys.argv) != 2:
        print("Использование: python nuclei.py путь_к_файлу.txt")
        sys.exit(1)
    
    input_file = sys.argv[1]
    
    # Проверяем существование файла
    if not os.path.exists(input_file):
        print(f"Ошибка: Файл '{input_file}' не найден.")
        sys.exit(1)
    
    try:
        # Читаем содержимое файла
        with open(input_file, 'r', encoding='utf-8') as f:
            text = f.read()
        
        vulnerabilities = parse_vulnerabilities(text)
        
        # Собираем данные из дополнительных файлов
        additional_files = {}
        base_dir = os.path.dirname(input_file)
        
        # Обрабатываем fuzz_output.txt
        ffuf_file = os.path.join(base_dir, "fuzz_output.txt")
        ffuf_results = parse_url_list_file(ffuf_file)
        if ffuf_results:
            additional_files["ffuf"] = ffuf_results
        
        # Обрабатываем sensitive.txt
        sensitive_file = os.path.join(base_dir, "sensitive.txt")
        sensitive_results = parse_url_list_file(sensitive_file)
        if sensitive_results:
            additional_files["sensitive"] = sensitive_results
        
        # Обрабатываем juicypath.txt
        juicypath_file = os.path.join(base_dir, "juicypath.txt")
        juicypath_results = parse_url_list_file(juicypath_file)
        if juicypath_results:
            additional_files["juicypath"] = juicypath_results
        
        # Обрабатываем s3scanner.txt
        s3scanner_file = os.path.join(base_dir, "s3scanner.txt")
        s3scanner_results = parse_s3scanner_file(s3scanner_file)
        if s3scanner_results:
            additional_files["s3scanner"] = s3scanner_results
        
        # Генерируем отчет с учетом всех дополнительных файлов
        html_report = generate_html_report(vulnerabilities, input_file, additional_files)
        
        # Формируем имя выходного файла
        output_file = os.path.splitext(input_file)[0] + "_report.html"
        
        # Сохраняем HTML отчет
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_report)
        
        print(f"Отчет успешно сгенерирован и сохранен в файл: {output_file}")
        print(f"Всего обработано уязвимостей Nuclei: {len(vulnerabilities)}")
        
        # Выводим информацию о дополнительных файлах
        for file_type, results in additional_files.items():
            print(f"Всего обработано результатов {file_type.capitalize()}: {len(results)}")
        
    except Exception as e:
        print(f"Ошибка при обработке файла: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
