import re
import sys
import os
import html
import json
from collections import defaultdict, Counter
from datetime import datetime

def strip_ansi_codes(text):
    """Remove ANSI escape codes from text"""
    ansi_pattern = r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])'
    return re.sub(ansi_pattern, '', text)

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
            extractor_text = brackets_match.group(2).strip()
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
    """Parse a file with URLs, one per line"""
    results = []
    
    if not os.path.exists(file_path):
        print(f"Warning: File '{file_path}' not found.")
        return results
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                url = line.strip()
                if url and url.startswith(('http://', 'https://')):
                    results.append(url)
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
    
    return results

def parse_s3scanner_file(file_path):
    """Parse a file with S3Scanner results"""
    results = []
    
    if not os.path.exists(file_path):
        print(f"Warning: File '{file_path}' not found.")
        return results
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
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
        print(f"Error reading file {file_path}: {e}")
    
    return results

def parse_subs_file(file_path):
    """Parse subs.txt with domains, one per line"""
    if not os.path.exists(file_path):
        print(f"Warning: File 'subs.txt' not found, using default value: 1")
        return 1
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            domains = {line.strip() for line in f if line.strip()}
        print(f"Found unique domains in subs.txt: {len(domains)}")
        return len(domains)
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return 1

def parse_alive_http_services_file(file_path):
    """Parse alive_http_services.txt with live hosts"""
    results = []
    
    if not os.path.exists(file_path):
        print(f"Warning: File 'alive_http_services.txt' not found.")
        return 0
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                url = line.strip()
                if url and url.startswith(('http://', 'https://')):
                    results.append(url)
        unique_hosts = len(set(results))
        print(f"Found unique live hosts: {unique_hosts}")
        return unique_hosts
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return 0

def parse_katana_file(file_path):
    """Parse katana.jsonl, returning unique endpoints"""
    endpoints = set()
    
    if not os.path.exists(file_path):
        print(f"Warning: File 'katana.jsonl' not found.")
        return endpoints
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    data = json.loads(line.strip())
                    endpoint = data.get('request', {}).get('endpoint')
                    if endpoint:
                        endpoints.add(endpoint)
                except json.JSONDecodeError as e:
                    print(f"Error parsing JSON in line: {e}")
        print(f"Found unique endpoints in katana.jsonl: {len(endpoints)}")
        return endpoints
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return endpoints

def parse_naabu_file(file_path):
    """Parse naabu.txt with port scanning results"""
    ports = []
    
    if not os.path.exists(file_path):
        print(f"Warning: File 'naabu.txt' not found.")
        return ports
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and ':' in line:
                    port = line.split(':')[-1]
                    if port.isdigit():
                        ports.append(port)
        port_counts = Counter(ports)
        print(f"Found ports in naabu.txt: {len(ports)}, unique: {len(port_counts)}")
        return port_counts
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return ports

def parse_katana_uniq_file(file_path):
    """Parse katana_uniq.txt with unique URLs"""
    urls = set()
    
    if not os.path.exists(file_path):
        print(f"Warning: File 'katana_uniq.txt' not found.")
        return urls
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                url = line.strip()
                if url and url.startswith(('http://', 'https://')):
                    urls.add(url)
        print(f"Found unique URLs in katana_uniq.txt: {len(urls)}")
        return urls
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return urls

def parse_tech_detect_file(file_path):
    """Parse tech-detect.txt with HTTP status codes and technologies"""
    status_codes = []
    technologies = []
    
    if not os.path.exists(file_path):
        print(f"Warning: File 'tech-detect.txt' not found.")
        return Counter(), Counter()
    
    try:
        # Пробуем открыть с учетом возможного BOM
        with open(file_path, 'r', encoding='utf-8-sig') as f:
            content = f.readlines()
            print(f"Read {len(content)} lines from tech-detect.txt")
            for i, line in enumerate(content, 1):
                line = line.strip()
                if not line:
                    print(f"Line {i}: Empty line, skipping")
                    continue
                # Удаляем ANSI escape-коды
                clean_line = strip_ansi_codes(line)
                print(f"Processing line {i}: {clean_line}")
                # Упрощенное регулярное выражение
                match = re.match(r'^(.*?)\s*\[(\d+)\](?:\s*\[(.*?)\])?$', clean_line)
                if match:
                    url, status_code, tech_list = match.groups()
                    print(f"Line {i} matched: URL={url}, Status={status_code}, Techs={tech_list}")
                    status_codes.append(status_code)
                    if tech_list:
                        techs = [tech.strip() for tech in tech_list.split(',') if tech.strip()]
                        print(f"Technologies found: {techs}")
                        technologies.extend(techs)
                    else:
                        print(f"No technologies found in line {i}")
                else:
                    print(f"Line {i} did not match regex: {clean_line}")
        status_counts = Counter(status_codes)
        tech_counts = Counter(technologies)
        print(f"Found status codes in tech-detect.txt: {len(status_codes)}, unique: {len(status_counts)}")
        print(f"Found technologies in tech-detect.txt: {len(technologies)}, unique: {len(tech_counts)}")
        return status_counts, tech_counts
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return Counter(), Counter()

def generate_html_report(vulnerabilities, input_filename, additional_files=None):
    if additional_files is None:
        additional_files = {}
    
    # Группировка уязвимостей по критичности
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    vuln_by_severity = defaultdict(list)
    
    for vuln in vulnerabilities:
        severity = vuln["severity"].lower()
        vuln_by_severity[severity].append(vuln)
    
    # Чтение данных для Dashboard
    base_dir = os.path.dirname(input_filename)
    unique_assets = parse_subs_file(os.path.join(base_dir, "subs.txt"))
    live_assets = parse_alive_http_services_file(os.path.join(base_dir, "alive_http_services.txt"))
    
    # Получение endpoints из katana.jsonl
    katana_endpoints = parse_katana_file(os.path.join(base_dir, "katana.jsonl"))
    app_endpoints = len(katana_endpoints)
    
    # Получение URLs из katana.jsonl и katana_uniq.txt для URLs Found
    katana_uniq_urls = parse_katana_uniq_file(os.path.join(base_dir, "katana_uniq.txt"))
    all_urls = katana_endpoints | katana_uniq_urls
    urls_found = len(all_urls)
    
    # Получение данных для Top 10 Ports из naabu.txt
    port_counts = parse_naabu_file(os.path.join(base_dir, "naabu.txt"))
    top_ports = dict(sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:10])
    
    # Получение данных для HTTP Status Codes и Top 10 Technologies из tech-detect.txt
    status_counts, tech_counts = parse_tech_detect_file(os.path.join(base_dir, "tech-detect.txt"))
    http_status_codes = dict(sorted(status_counts.items(), key=lambda x: x[1], reverse=True)[:10])
    top_tech = dict(sorted(tech_counts.items(), key=lambda x: x[1], reverse=True)[:10])
    
    # Отладочные сообщения
    print(f"Dashboard values: unique_assets={unique_assets}, live_assets={live_assets}, app_endpoints={app_endpoints}, urls_found={urls_found}")
    print(f"Top 10 Ports: {top_ports}")
    print(f"HTTP Status Codes: {http_status_codes}")
    print(f"Top 10 Technologies: {top_tech}")
    
    # HTML шаблон
    report_title = os.path.splitext(os.path.basename(input_filename))[0]
    html_output = f"""<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Report: {html.escape(report_title)}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
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
        .dashboard h2 {{ background-color: #1abc9c; }}
        
        .vuln-table {{
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
            margin-bottom: 30px;
            table-layout: fixed;
        }}
        .vuln-table th, .vuln-table td {{
            border: 1px solid #ddd;
            padding: 10px;
            text-align: left;
            vertical-align: top;
            overflow-wrap: break-word;
        }}
        .vuln-table th {{
            background-color: #f2f2f2;
        }}
        .vuln-table tr:nth-child(even) {{
            background-color: #f9f9f9;
        }}
        .vuln-table th:nth-child(1), .vuln-table td:nth-child(1) {{ width: 20%; }}
        .vuln-table th:nth-child(2), .vuln-table td:nth-child(2) {{ width: 10%; }}
        .vuln-table th:nth-child(3), .vuln-table td:nth-child(3) {{ width: 45%; }}
        .vuln-table th:nth-child(4), .vuln-table td:nth-child(4) {{ 
            width: 25%; 
            position: relative;
            height: 100%;
            padding: 0;
        }}
        .two-col-table th:nth-child(1), .two-col-table td:nth-child(1) {{ width: 10%; }}
        .two-col-table th:nth-child(2), .two-col-table td:nth-child(2) {{ width: 90%; }}
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
        .no-results {{
            text-align: center;
            color: #7f8c8d;
            font-style: italic;
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
        .dashboard-stats {{
            display: flex;
            justify-content: space-between;
            margin-bottom: 30px;
        }}
        .stat-card {{
            flex: 1;
            background-color: #3498db;
            color: white;
            padding: 20px;
            margin: 0 10px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 5px rgba(0,0,0,0.2);
        }}
        .stat-card h3 {{
            margin: 0 0 10px 0;
            font-size: 1.2em;
        }}
        .stat-card p {{
            margin: 0;
            font-size: 2em;
            font-weight: bold;
        }}
        .chart-container {{
            margin-bottom: 30px;
            background-color: #fff;
            padding: 15px;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            max-width: 500px;
        }}
        canvas {{
            max-width: 100%;
            height: 200px !important;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Vulnerability Report</h1>
        <div class="source-file">Vulnerability Report File: {html.escape(input_filename)}</div>
        
        <div class="summary">
            <h3>Summary information</h3>
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
                    <td>Total</td>
                    <td>{len(vulnerabilities)}</td>
                </tr>
"""

    # Добавляем информацию о дополнительных файлах в таблицу
    for file_type, file_data in additional_files.items():
        if file_data and len(file_data) > 0:
            file_name = {"ffuf": "Ffuf findings", 
                         "sensitive": "Sensitive findings", 
                         "juicypath": "JuicyPath findings",
                         "s3scanner": "S3Scanner findings"}.get(file_type, file_type)
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
            <button class="tablinks active" onclick="openTab(event, 'DashboardTab')">Dashboard</button>
            <button class="tablinks" onclick="openTab(event, 'NucleiTab')">Nuclei</button>
"""

    # Добавляем вкладки для дополнительных файлов
    for file_type, file_data in additional_files.items():
        if file_data and len(file_data) > 0:
            tab_name = {"ffuf": "Ffuf", 
                        "sensitive": "Sensitive", 
                        "juicypath": "JuicyPath",
                        "s3scanner": "S3Scanner"}.get(file_type, file_type.capitalize())
            html_output += f"""
            <button class="tablinks" onclick="openTab(event, '{file_type.capitalize()}Tab')">{tab_name}</button>
"""

    html_output += f"""
        </div>
        
        <div id="DashboardTab" class="tabcontent" style="display: block;">
            <div class="dashboard">
                <h2>Dashboard</h2>
                <div class="dashboard-stats">
                    <div class="stat-card">
                        <h3>Total Unique Assets</h3>
                        <p>{unique_assets}</p>
                    </div>
                    <div class="stat-card">
                        <h3>Total Live Assets</h3>
                        <p>{live_assets}</p>
                    </div>
                    <div class="stat-card">
                        <h3>Application Endpoints</h3>
                        <p>{app_endpoints}</p>
                    </div>
                </div>
                <div class="chart-container">
                    <h3>Assets Overview</h3>
                    <canvas id="assetsChart"></canvas>
                </div>
                <div class="chart-container">
                    <h3>HTTP Status Codes</h3>
"""

    if http_status_codes:
        html_output += '<canvas id="statusChart"></canvas>'
    else:
        html_output += '<p class="no-results">No results</p>'

    html_output += """
                </div>
                <div class="chart-container">
                    <h3>Top 10 Ports</h3>
"""

    if top_ports:
        html_output += '<canvas id="portsChart"></canvas>'
    else:
        html_output += '<p class="no-results">No results</p>'

    html_output += """
                </div>
                <div class="chart-container">
                    <h3>Top 10 Technologies</h3>
"""

    if top_tech:
        html_output += '<canvas id="techChart"></canvas>'
    else:
        html_output += '<p class="no-results">No results</p>'

    html_output += f"""
                </div>
                <div class="chart-container">
                    <h3>URLs Found</h3>
                    <canvas id="urlsChart"></canvas>
                </div>
            </div>
        </div>
        
        <div id="NucleiTab" class="tabcontent">
"""

    if not vulnerabilities:
        html_output += """
            <div class="no-vulns">
                <p>No vulnerabilities found in the report. Please check the input file format.</p>
            </div>
        """
    else:
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
                                <th>CVE/Template</th>
                                <th>Protocol</th>
                                <th>URL</th>
                                <th>Additional information</th>
                            </tr>
                        </thead>
                        <tbody>
"""
            for vuln in vulns:
                cve_escaped = html.escape(vuln["cve_or_type"])
                protocol_escaped = html.escape(vuln["protocol"])
                url_escaped = html.escape(vuln["url"])
                
                extractors_html = ""
                if vuln["extractors"]:
                    extractors_html = '<div class="scroll-container"><div class="extractors-cell">'
                    for extractor in vuln["extractors"]:
                        extractors_html += f'<span class="extractor">{html.escape(extractor)}</span> '
                    extractors_html += '</div></div>'
                else:
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
            tab_title = {"ffuf": "FFUF RESULTS", 
                         "sensitive": "SENSITIVE RESULTS", 
                         "juicypath": "JUICYPATH RESULTS",
                         "s3scanner": "S3SCANNER RESULTS"}.get(file_type, f"{file_type.upper()} RESULTS")
            
            if file_type == "s3scanner":
                html_output += f"""
        <div id="{tab_name}Tab" class="tabcontent">
            <div class="{file_type}">
                <h2>{tab_title}</h2>
                <table class="vuln-table s3scanner-table">
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>Bucket Name</th>
                            <th>Region</th>
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
                html_output += f"""
        <div id="{tab_name}Tab" class="tabcontent">
            <div class="{file_type}">
                <h2>{tab_title}</h2>
                <table class="vuln-table two-col-table">
                    <thead>
                        <tr>
                            <th>#</th>
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

    # JavaScript для вкладок и графиков
    html_output += f"""
        <script>
        function openTab(evt, tabName) {{
            var i, tabcontent, tablinks;
            tabcontent = document.getElementsByClassName("tabcontent");
            for (i = 0; i < tabcontent.length; i++) {{
                tabcontent[i].style.display = "none";
            }}
            tablinks = document.getElementsByClassName("tablinks");
            for (i = 0; i < tablinks.length; i++) {{
                tablinks[i].className = tablinks[i].className.replace(" active", "");
            }}
            document.getElementById(tabName).style.display = "block";
            evt.currentTarget.className += " active";
        }}
        
        document.addEventListener('DOMContentLoaded', function() {{
            var scrollContainers = document.querySelectorAll('.scroll-container');
            scrollContainers.forEach(function(container) {{
                if (container.scrollHeight > container.clientHeight) {{
                    container.style.borderColor = '#ccc';
                }} else {{
                    container.style.borderColor = '#f0f0f0';
                }}
            }});
            
            // График Assets Overview
            new Chart(document.getElementById('assetsChart'), {{
                type: 'bar',
                data: {{
                    labels: ['Total Assets', 'Live Assets', 'Application Endpoints'],
                    datasets: [{{
                        label: 'Count',
                        data: [{unique_assets}, {live_assets}, {app_endpoints}],
                        backgroundColor: ['#3498db', '#2ecc71', '#e74c3c']
                    }}]
                }},
                options: {{
                    scales: {{
                        y: {{ beginAtZero: true }}
                    }},
                    plugins: {{
                        legend: {{ display: false }}
                    }}
                }}
            }});
"""

    # Добавляем JavaScript для графиков только если есть данные
    if http_status_codes:
        html_output += f"""
            // График HTTP Status Codes
            new Chart(document.getElementById('statusChart'), {{
                type: 'bar',
                data: {{
                    labels: {list(http_status_codes.keys())},
                    datasets: [{{
                        label: 'Count',
                        data: {list(http_status_codes.values())},
                        backgroundColor: '#3498db'
                    }}]
                }},
                options: {{
                    scales: {{
                        y: {{ beginAtZero: true }}
                    }},
                    plugins: {{
                        legend: {{ display: false }}
                    }}
                }}
            }});
"""

    if top_ports:
        html_output += f"""
            // График Top 10 Ports
            new Chart(document.getElementById('portsChart'), {{
                type: 'bar',
                data: {{
                    labels: {list(top_ports.keys())},
                    datasets: [{{
                        label: 'Count',
                        data: {list(top_ports.values())},
                        backgroundColor: '#2ecc71'
                    }}]
                }},
                options: {{
                    scales: {{
                        y: {{ beginAtZero: true }}
                    }},
                    plugins: {{
                        legend: {{ display: false }}
                    }}
                }}
            }});
"""

    if top_tech:
        html_output += f"""
            // График Top 10 Technologies
            new Chart(document.getElementById('techChart'), {{
                type: 'bar',
                data: {{
                    labels: {list(top_tech.keys())},
                    datasets: [{{
                        label: 'Count',
                        data: {list(top_tech.values())},
                        backgroundColor: '#e74c3c'
                    }}]
                }},
                options: {{
                    scales: {{
                        y: {{ beginAtZero: true }}
                    }},
                    plugins: {{
                        legend: {{ display: false }}
                    }}
                }}
            }});
"""

    html_output += f"""
            // График URLs Found
            new Chart(document.getElementById('urlsChart'), {{
                type: 'bar',
                data: {{
                    labels: ['URLs Found'],
                    datasets: [{{
                        label: 'Count',
                        data: [{urls_found}],
                        backgroundColor: '#9b59b6'
                    }}]
                }},
                options: {{
                    scales: {{
                        y: {{ beginAtZero: true }}
                    }},
                    plugins: {{
                        legend: {{ display: false }}
                    }}
                }}
            }});
        }});
        </script>
"""

    # Завершаем HTML
    current_date = datetime.now().strftime("%d.%m.%Y %H:%M")
    html_output += f"""
        <footer>
            Report generated: {current_date}
        </footer>
    </div>
</body>
</html>
"""
    return html_output

def main():
    if len(sys.argv) != 2:
        print("Usage: python nuclei.py input_file.txt")
        sys.exit(1)
    
    input_file = sys.argv[1]
    
    if not os.path.exists(input_file):
        print(f"Error: File '{input_file}' not found.")
        sys.exit(1)
    
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            text = f.read()
        
        vulnerabilities = parse_vulnerabilities(text)
        
        additional_files = {}
        base_dir = os.path.dirname(input_file)
        
        ffuf_file = os.path.join(base_dir, "fuzz_output.txt")
        ffuf_results = parse_url_list_file(ffuf_file)
        if ffuf_results:
            additional_files["ffuf"] = ffuf_results
        
        sensitive_file = os.path.join(base_dir, "sensitive.txt")
        sensitive_results = parse_url_list_file(sensitive_file)
        if sensitive_results:
            additional_files["sensitive"] = sensitive_results
        
        juicypath_file = os.path.join(base_dir, "juicypath.txt")
        juicypath_results = parse_url_list_file(juicypath_file)
        if juicypath_results:
            additional_files["juicypath"] = juicypath_results
        
        s3scanner_file = os.path.join(base_dir, "s3scanner.txt")
        s3scanner_results = parse_s3scanner_file(s3scanner_file)
        if s3scanner_results:
            additional_files["s3scanner"] = s3scanner_results
        
        html_report = generate_html_report(vulnerabilities, input_file, additional_files)
        
        output_file = os.path.splitext(input_file)[0] + "_report.html"
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_report)
        
        print(f"Report successfully generated and saved to: {output_file}")
        print(f"Total Nuclei vulnerabilities processed: {len(vulnerabilities)}")
        
        for file_type, results in additional_files.items():
            print(f"Total {file_type.capitalize()} results processed: {len(results)}")
        
    except Exception as e:
        print(f"Error processing file: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
