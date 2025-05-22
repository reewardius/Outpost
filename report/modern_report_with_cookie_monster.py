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
    pattern = r'\[(.*?)\] \[(.*?)\] \[(.*?)\] (.*?)(?=$)'
    vulns = []
    
    for match in re.finditer(pattern, text, re.MULTILINE):
        cve_or_type, protocol, severity, remaining_text = match.groups()
        url = remaining_text.strip()
        extractors = []
        
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

def parse_cookiemonster_file(file_path):
    results = []
    if not os.path.exists(file_path):
        print(f"Warning: File '{file_path}' not found.")
        return results
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            blocks = content.split('########## RESULT END ##########')
            for block in blocks:
                block = block.strip()
                if not block:
                    continue
                target_match = re.search(r'\[\+\] Target: (.*?)\s*\|\s*Cookie: (.*?)\s*$', block, re.MULTILINE)
                key_match = re.search(r'Success! I discovered the key for this cookie with the jwt decoder; it is "(.*?)"', block)
                if target_match and key_match:
                    target, cookie = target_match.groups()
                    key = key_match.group(1)
                    results.append({
                        "target": target.strip(),
                        "cookie": cookie.strip(),
                        "key": key.strip()
                    })
        print(f"Found CookieMonster results: {len(results)}")
        return results
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return results

def parse_subs_file(file_path):
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
    status_codes = []
    technologies = []
    if not os.path.exists(file_path):
        print(f"Warning: File 'tech-detect.txt' not found.")
        return Counter(), Counter()
    
    try:
        with open(file_path, 'r', encoding='utf-8-sig') as f:
            content = f.readlines()
            for i, line in enumerate(content, 1):
                line = line.strip()
                if not line:
                    continue
                clean_line = strip_ansi_codes(line)
                match = re.match(r'^(.*?)\s*\[(\d+)\](?:\s*\[(.*?)\])?$', clean_line)
                if match:
                    url, status_code, tech_list = match.groups()
                    status_codes.append(status_code)
                    if tech_list:
                        techs = [tech.strip() for tech in tech_list.split(',') if tech.strip()]
                        technologies.extend(techs)
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
    
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    vuln_by_severity = defaultdict(list)
    
    for vuln in vulnerabilities:
        severity = vuln["severity"].lower()
        vuln_by_severity[severity].append(vuln)
    
    print("Nuclei vulnerabilities breakdown:")
    for severity in severity_order:
        count = len(vuln_by_severity.get(severity, []))
        print(f"{severity.capitalize()}: {count}")
    print(f"Total vulnerabilities: {len(vulnerabilities)}")
    
    base_dir = os.path.dirname(input_filename)
    unique_assets = parse_subs_file(os.path.join(base_dir, "subs.txt"))
    live_assets = parse_alive_http_services_file(os.path.join(base_dir, "alive_http_services.txt"))
    katana_endpoints = parse_katana_file(os.path.join(base_dir, "katana.jsonl"))
    app_endpoints = len(katana_endpoints)
    katana_uniq_urls = parse_katana_uniq_file(os.path.join(base_dir, "katana_uniq.txt"))
    all_urls = katana_endpoints | katana_uniq_urls
    urls_found = len(all_urls)
    port_counts = parse_naabu_file(os.path.join(base_dir, "naabu.txt"))
    top_ports = dict(sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:10])
    status_counts, tech_counts = parse_tech_detect_file(os.path.join(base_dir, "tech-detect.txt"))
    http_status_codes = dict(sorted(status_counts.items(), key=lambda x: x[1], reverse=True)[:10])
    top_tech = dict(sorted(tech_counts.items(), key=lambda x: x[1], reverse=True)[:10])
    
    print(f"Dashboard values - unique_assets: {unique_assets}, live_assets: {live_assets}, app_endpoints: {app_endpoints}, urls_found: {urls_found}")
    
    unique_assets_display = str(unique_assets) if unique_assets > 0 else "No data"
    live_assets_display = str(live_assets) if live_assets > 0 else "No data"
    app_endpoints_display = str(app_endpoints) if app_endpoints > 0 else "No data"
    
    print(f"Display values - unique_assets_display: {unique_assets_display}, live_assets_display: {live_assets_display}, app_endpoints_display: {app_endpoints_display}")
    
    report_title = os.path.splitext(os.path.basename(input_filename))[0]
    html_output = """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Report: """ + html.escape(report_title) + """</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        .tablinks.active {
            background-color: #3b82f6;
            color: white;
        }
        .scroll-container {
            max-height: 120px;
            overflow-y: auto;
        }
        .chart-container canvas {
            max-height: 300px !important;
        }
        .dark .bg-white {
            background-color: #1f2937;
        }
        .dark .text-gray-700 {
            color: #d1d5db;
        }
        .dark .bg-gray-50 {
            background-color: #374151;
        }
        .dark .border-b {
            border-color: #4b5563;
        }
        .dark .bg-red-100 {
            background-color: #7f1d1d;
        }
        .dark .bg-orange-100 {
            background-color: #7c2d12;
        }
        .dark .bg-yellow-100 {
            background-color: #713f12;
        }
        .dark .bg-green-100 {
            background-color: #14532d;
        }
        .dark .bg-blue-100 {
            background-color: #1e3a8a;
        }
        .dark .bg-gray-100 {
            background-color: #374151;
        }
        .dark .bg-purple-100 {
            background-color: #4c1d95;
        }
        .dark .bg-indigo-100 {
            background-color: #312e81;
        }
        .dark .text-red-700, .dark .text-orange-700, .dark .text-yellow-700, .dark .text-green-700, .dark .text-blue-700, .dark .text-gray-700, .dark .text-purple-700, .dark .text-indigo-700 {
            color: #d1d5db;
        }
        .dark .bg-gray-800 {
            background-color: #111827;
        }
        .dark .text-gray-600 {
            color: #9ca3af;
        }
        .dark .bg-gray-200 {
            background-color: #4b5563;
        }
        .dark .text-gray-500 {
            color: #9ca3af;
        }
        .dark .shadow-md {
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2), 0 2px 4px -1px rgba(0, 0, 0, 0.12);
        }
    </style>
</head>
<body class="bg-gray-100 dark:bg-gray-900 font-sans leading-normal tracking-normal transition-colors duration-300">
    <div class="container max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <header class="mb-8 flex justify-between items-center">
            <div>
                <h1 class="text-4xl font-bold text-gray-900 dark:text-white">Vulnerability Report</h1>
                <p class="text-sm text-gray-600 dark:text-gray-400 mt-2">Source: """ + html.escape(input_filename) + """</p>
            </div>
            <button id="themeToggle" class="p-2 rounded-full bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-300 dark:hover:bg-gray-600 transition">
                <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"></path></svg>
            </button>
        </header>

        <section class="bg-white dark:bg-gray-800 rounded-lg shadow-md p-6 mb-8">
            <h2 class="text-2xl font-semibold text-gray-800 dark:text-white mb-4">Summary</h2>
            <div class="mb-6">
                <h3 class="text-xl font-medium text-gray-800 dark:text-white mb-3">Nuclei Vulnerabilities</h3>
                <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                    <div class="bg-red-100 dark:bg-red-900 p-6 rounded-lg min-h-[100px]">
                        <span class="text-red-700 dark:text-red-300 font-medium text-sm">Critical</span>
                        <p class="text-xl font-bold text-red-800 dark:text-red-200">""" + str(len(vuln_by_severity.get("critical", []))) + """</p>
                    </div>
                    <div class="bg-orange-100 dark:bg-orange-900 p-6 rounded-lg min-h-[100px]">
                        <span class="text-orange-700 dark:text-orange-300 font-medium text-sm">High</span>
                        <p class="text-xl font-bold text-orange-800 dark:text-orange-200">""" + str(len(vuln_by_severity.get("high", []))) + """</p>
                    </div>
                    <div class="bg-yellow-100 dark:bg-yellow-900 p-6 rounded-lg min-h-[100px]">
                        <span class="text-yellow-700 dark:text-yellow-300 font-medium text-sm">Medium</span>
                        <p class="text-xl font-bold text-yellow-800 dark:text-yellow-200">""" + str(len(vuln_by_severity.get("medium", []))) + """</p>
                    </div>
                    <div class="bg-green-100 dark:bg-green-900 p-6 rounded-lg min-h-[100px]">
                        <span class="text-green-700 dark:text-green-300 font-medium text-sm">Low</span>
                        <p class="text-xl font-bold text-green-800 dark:text-green-200">""" + str(len(vuln_by_severity.get("low", []))) + """</p>
                    </div>
                    <div class="bg-blue-100 dark:bg-blue-900 p-6 rounded-lg min-h-[100px]">
                        <span class="text-blue-700 dark:text-blue-300 font-medium text-sm">Info</span>
                        <p class="text-xl font-bold text-blue-800 dark:text-blue-200">""" + str(len(vuln_by_severity.get("info", []))) + """</p>
                    </div>
                    <div class="bg-gray-100 dark:bg-gray-700 p-6 rounded-lg min-h-[100px]">
                        <span class="text-gray-700 dark:text-gray-300 font-medium text-sm">Unknown</span>
                        <p class="text-xl font-bold text-gray-800 dark:text-gray-200">""" + str(len(vuln_by_severity.get("unknown", []))) + """</p>
                    </div>
                    <div class="bg-purple-100 dark:bg-purple-900 p-6 rounded-lg min-h-[100px]">
                        <span class="text-purple-700 dark:text-purple-300 font-medium text-sm">Total</span>
                        <p class="text-xl font-bold text-purple-800 dark:text-purple-200">""" + str(len(vulnerabilities)) + """</p>
                    </div>
                </div>
            </div>
            <div>
                <h3 class="text-xl font-medium text-gray-800 dark:text-white mb-3">Additional Findings</h3>
                <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
"""

    for file_type, file_data in additional_files.items():
        if file_data and len(file_data) > 0:
            file_name = {
                "ffuf": "Ffuf Findings",
                "sensitive": "Sensitive Findings",
                "juicypath": "JuicyPath Findings",
                "s3scanner": "S3Scanner Findings",
                "cookiemonster": "CookieMonster Findings"
            }.get(file_type, file_type)
            html_output += """
                    <div class="bg-indigo-100 dark:bg-indigo-900 p-6 rounded-lg min-h-[100px]">
                        <span class="text-indigo-700 dark:text-indigo-300 font-medium text-sm">""" + file_name + """</span>
                        <p class="text-xl font-bold text-indigo-800 dark:text-indigo-200">""" + str(len(file_data)) + """</p>
                    </div>
"""

    html_output += """
                </div>
            </div>
        </section>

        <nav class="bg-gray-800 dark:bg-gray-950 rounded-t-lg overflow-x-auto mb-0">
            <div class="flex">
                <button class="tablinks active px-4 py-3 text-white font-medium hover:bg-gray-700 dark:hover:bg-gray-800 focus:outline-none" onclick="openTab(event, 'DashboardTab')">Dashboard</button>
                <button class="tablinks px-4 py-3 text-white font-medium hover:bg-gray-700 dark:hover:bg-gray-800 focus:outline-none" onclick="openTab(event, 'NucleiTab')">Nuclei</button>
"""

    for file_type, file_data in additional_files.items():
        if file_data and len(file_data) > 0:
            tab_name = {
                "ffuf": "Ffuf",
                "sensitive": "Sensitive",
                "juicypath": "JuicyPath",
                "s3scanner": "S3Scanner",
                "cookiemonster": "CookieMonster"
            }.get(file_type, file_type.capitalize())
            html_output += f"""
                <button class="tablinks px-4 py-3 text-white font-medium hover:bg-gray-700 dark:hover:bg-gray-800 focus:outline-none" onclick="openTab(event, '{tab_name}Tab')">{tab_name}</button>
"""

    html_output += """
            </div>
        </nav>

        <div id="DashboardTab" class="tabcontent bg-white dark:bg-gray-800 rounded-b-lg shadow-md p-6" style="display: block;">
            <h2 class="text-2xl font-semibold text-gray-800 dark:text-white mb-4">Dashboard</h2>
            <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
                <div class="bg-blue-600 dark:bg-blue-700 text-white p-6 rounded-lg shadow">
                    <h3 class="text-lg font-medium">Total Unique Assets</h3>
                    <p class="text-3xl font-bold">""" + unique_assets_display + """</p>
                </div>
                <div class="bg-green-600 dark:bg-green-700 text-white p-6 rounded-lg shadow">
                    <h3 class="text-lg font-medium">Total Live Assets</h3>
                    <p class="text-3xl font-bold">""" + live_assets_display + """</p>
                </div>
                <div class="bg-red-600 dark:bg-red-700 text-white p-6 rounded-lg shadow">
                    <h3 class="text-lg font-medium">Application Endpoints</h3>
                    <p class="text-3xl font-bold">""" + app_endpoints_display + """</p>
                </div>
            </div>
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div class="chart-container bg-white dark:bg-gray-700 p-4 rounded-lg shadow">
                    <h3 class="text-lg font-semibold text-gray-800 dark:text-white mb-4">Assets Overview</h3>
                    <canvas id="assetsChart"></canvas>
                </div>
                <div class="chart-container bg-white dark:bg-gray-700 p-4 rounded-lg shadow">
                    <h3 class="text-lg font-semibold text-gray-800 dark:text-white mb-4">HTTP Status Codes</h3>
"""

    if http_status_codes:
        html_output += '<canvas id="statusChart"></canvas>'
    else:
        html_output += '<p class="text-gray-500 dark:text-gray-400 italic">No results</p>'

    html_output += """
                </div>
                <div class="chart-container bg-white dark:bg-gray-700 p-4 rounded-lg shadow">
                    <h3 class="text-lg font-semibold text-gray-800 dark:text-white mb-4">Top 10 Ports</h3>
"""

    if top_ports:
        html_output += '<canvas id="portsChart"></canvas>'
    else:
        html_output += '<p class="text-gray-500 dark:text-gray-400 italic">No results</p>'

    html_output += """
                </div>
                <div class="chart-container bg-white dark:bg-gray-700 p-4 rounded-lg shadow">
                    <h3 class="text-lg font-semibold text-gray-800 dark:text-white mb-4">Top 10 Technologies</h3>
"""

    if top_tech:
        html_output += '<canvas id="techChart"></canvas>'
    else:
        html_output += '<p class="text-gray-500 dark:text-gray-400 italic">No results</p>'

    html_output += """
                </div>
                <div class="chart-container bg-white dark:bg-gray-700 p-4 rounded-lg shadow">
                    <h3 class="text-lg font-semibold text-gray-800 dark:text-white mb-4">URLs Found</h3>
                    <canvas id="urlsChart"></canvas>
                </div>
            </div>
        </div>

        <div id="NucleiTab" class="tabcontent bg-white dark:bg-gray-800 rounded-b-lg shadow-md p-6 hidden">
"""

    if not vulnerabilities:
        html_output += """
            <div class="bg-red-100 dark:bg-red-900 text-red-700 dark:text-red-300 p-4 rounded-lg">
                <p>No vulnerabilities found in the report. Please check the input file format.</p>
            </div>
"""
    else:
        for severity_name in sorted(vuln_by_severity.keys(), key=lambda x: severity_order.get(x, 999)):
            vulns = vuln_by_severity[severity_name]
            if not vulns:
                continue
            severity_display = severity_name.upper()
            severity_color = {
                "critical": "bg-red-600 dark:bg-red-700",
                "high": "bg-orange-600 dark:bg-orange-700",
                "medium": "bg-yellow-600 dark:bg-yellow-700",
                "low": "bg-green-600 dark:bg-green-700",
                "info": "bg-blue-600 dark:bg-blue-700",
                "unknown": "bg-gray-600 dark:bg-gray-700"
            }.get(severity_name, "bg-gray-600 dark:bg-gray-700")
            html_output += f"""
                <div class="mb-8">
                    <h2 class="{severity_color} text-white px-4 py-2 rounded-t-lg">{severity_display} ({len(vulns)})</h2>
                    <div class="overflow-x-auto">
                        <table class="min-w-full bg-white dark:bg-gray-800">
                            <thead>
                                <tr class="bg-gray-50 dark:bg-gray-700">
                                    <th class="px-4 py-2 text-left text-sm font-medium text-gray-700 dark:text-gray-300">CVE/Template</th>
                                    <th class="px-4 py-2 text-left text-sm font-medium text-gray-700 dark:text-gray-300">Protocol</th>
                                    <th class="px-4 py-2 text-left text-sm font-medium text-gray-700 dark:text-gray-300 min-w-[300px]">URL</th>
                                    <th class="px-4 py-2 text-left text-sm font-medium text-gray-700 dark:text-gray-300">Additional Information</th>
                                </tr>
                            </thead>
                            <tbody>
"""
            for vuln in vulns:
                cve_escaped = html.escape(vuln["cve_or_type"])
                protocol_escaped = html.escape(vuln["protocol"])
                url_escaped = html.escape(vuln["url"])
                extractors_html = '<div class="scroll-container p-2 bg-gray-50 dark:bg-gray-700 rounded"><div class="space-y-1">'
                if vuln["extractors"]:
                    for extractor in vuln["extractors"]:
                        extractors_html += f'<span class="inline-block bg-gray-200 dark:bg-gray-600 text-gray-700 dark:text-gray-300 px-2 py-1 rounded text-sm">{html.escape(extractor)}</span>'
                else:
                    extractors_html += '<span class="text-gray-500 dark:text-gray-400">None</span>'
                extractors_html += '</div></div>'
                html_output += f"""
                                <tr class="border-b dark:border-gray-700">
                                    <td class="px-4 py-3 text-sm text-gray-800 dark:text-gray-200">{cve_escaped}</td>
                                    <td class="px-4 py-3 text-sm text-gray-800 dark:text-gray-200">{protocol_escaped}</td>
                                    <td class="px-4 py-3 text-sm break-all break-words max-w-[400px]"><a href="{url_escaped}" target="_blank" class="text-blue-600 dark:text-blue-400 hover:underline">{url_escaped}</a></td>
                                    <td class="px-4 py-3">{extractors_html}</td>
                                </tr>
"""
            html_output += """
                            </tbody>
                        </table>
                    </div>
                </div>
"""

    html_output += """
        </div>
"""

    for file_type, file_data in additional_files.items():
        if file_data and len(file_data) > 0:
            tab_name = {
                "ffuf": "Ffuf",
                "sensitive": "Sensitive",
                "juicypath": "JuicyPath",
                "s3scanner": "S3Scanner",
                "cookiemonster": "CookieMonster"
            }.get(file_type, file_type.capitalize())
            tab_title = {
                "ffuf": "FFUF RESULTS",
                "sensitive": "SENSITIVE RESULTS",
                "juicypath": "JUICYPATH RESULTS",
                "s3scanner": "S3SCANNER RESULTS",
                "cookiemonster": "COOKIEMONSTER RESULTS"
            }.get(file_type, f"{file_type.upper()} RESULTS")
            tab_color = {
                "ffuf": "bg-purple-600 dark:bg-purple-700",
                "sensitive": "bg-indigo-600 dark:bg-indigo-700",
                "juicypath": "bg-teal-600 dark:bg-teal-700",
                "s3scanner": "bg-green-600 dark:bg-green-700",
                "cookiemonster": "bg-cyan-600 dark:bg-cyan-700"
            }.get(file_type, "bg-gray-600 dark:bg-gray-700")
            
            if file_type == "s3scanner":
                html_output += f"""
        <div id="{tab_name}Tab" class="tabcontent bg-white dark:bg-gray-800 rounded-b-lg shadow-md p-6 hidden">
            <h2 class="{tab_color} text-white px-4 py-2 rounded-t-lg">{tab_title}</h2>
            <div class="overflow-x-auto">
                <table class="min-w-full bg-white dark:bg-gray-800">
                    <thead>
                        <tr class="bg-gray-50 dark:bg-gray-700">
                            <th class="px-4 py-2 text-left text-sm font-medium text-gray-700 dark:text-gray-300">#</th>
                            <th class="px-4 py-2 text-left text-sm font-medium text-gray-700 dark:text-gray-300">Bucket Name</th>
                            <th class="px-4 py-2 text-left text-sm font-medium text-gray-700 dark:text-gray-300">Region</th>
                            <th class="px-4 py-2 text-left text-sm font-medium text-gray-700 dark:text-gray-300">AuthUsers</th>
                            <th class="px-4 py-2 text-left text-sm font-medium text-gray-700 dark:text-gray-300">AllUsers</th>
                        </tr>
                    </thead>
                    <tbody>
"""
                for i, bucket_data in enumerate(file_data, 1):
                    bucket_name = html.escape(bucket_data["bucket_name"])
                    region = html.escape(bucket_data["region"])
                    auth_users = html.escape(bucket_data["auth_users"])
                    all_users = html.escape(bucket_data["all_users"])
                    row_class = "bg-yellow-100 dark:bg-yellow-900" if "READ" in all_users else ""
                    html_output += f"""
                        <tr class="{row_class} border-b dark:border-gray-700">
                            <td class="px-4 py-3 text-sm text-gray-800 dark:text-gray-200">{i}</td>
                            <td class="px-4 py-3 text-sm text-gray-800 dark:text-gray-200">{bucket_name}</td>
                            <td class="px-4 py-3 text-sm text-gray-800 dark:text-gray-200">{region}</td>
                            <td class="px-4 py-3 text-sm text-gray-800 dark:text-gray-200">{auth_users}</td>
                            <td class="px-4 py-3 text-sm text-gray-800 dark:text-gray-200">{all_users}</td>
                        </tr>
"""
            elif file_type == "cookiemonster":
                html_output += f"""
        <div id="{tab_name}Tab" class="tabcontent bg-white dark:bg-gray-800 rounded-b-lg shadow-md p-6 hidden">
            <h2 class="{tab_color} text-white px-4 py-2 rounded-t-lg">{tab_title}</h2>
            <div class="overflow-x-auto">
                <table class="min-w-full bg-white dark:bg-gray-800">
                    <thead>
                        <tr class="bg-gray-50 dark:bg-gray-700">
                            <th class="px-4 py-2 text-left text-sm font-medium text-gray-700 dark:text-gray-300">#</th>
                            <th class="px-4 py-2 text-left text-sm font-medium text-gray-700 dark:text-gray-300 min-w-[300px]">Target</th>
                            <th class="px-4 py-2 text-left text-sm font-medium text-gray-700 dark:text-gray-300 min-w-[300px]">Cookie</th>
                            <th class="px-4 py-2 text-left text-sm font-medium text-gray-700 dark:text-gray-300">Key</th>
                        </tr>
                    </thead>
                    <tbody>
"""
                for i, data in enumerate(file_data, 1):
                    target = html.escape(data["target"])
                    cookie = html.escape(data["cookie"])
                    key = html.escape(data["key"])
                    html_output += f"""
                        <tr class="border-b dark:border-gray-700">
                            <td class="px-4 py-3 text-sm text-gray-800 dark:text-gray-200">{i}</td>
                            <td class="px-4 py-3 text-sm break-all break-words max-w-[400px]"><a href="{target}" target="_blank" class="text-blue-600 dark:text-blue-400 hover:underline">{target}</a></td>
                            <td class="px-4 py-3 text-sm break-all break-words max-w-[400px] text-white">{cookie}</td>
                            <td class="px-4 py-3 text-sm text-gray-800 dark:text-gray-200">{key}</td>
                        </tr>
"""
            else:
                html_output += f"""
        <div id="{tab_name}Tab" class="tabcontent bg-white dark:bg-gray-800 rounded-b-lg shadow-md p-6 hidden">
            <h2 class="{tab_color} text-white px-4 py-2 rounded-t-lg">{tab_title}</h2>
            <div class="overflow-x-auto">
                <table class="min-w-full bg-white dark:bg-gray-800">
                    <thead>
                        <tr class="bg-gray-50 dark:bg-gray-700">
                            <th class="px-4 py-2 text-left text-sm font-medium text-gray-700 dark:text-gray-300">#</th>
                            <th class="px-4 py-2 text-left text-sm font-medium text-gray-700 dark:text-gray-300 min-w-[300px]">URL</th>
                        </tr>
                    </thead>
                    <tbody>
"""
                for i, url in enumerate(file_data, 1):
                    url_escaped = html.escape(url)
                    html_output += f"""
                        <tr class="border-b dark:border-gray-700">
                            <td class="px-4 py-3 text-sm text-gray-800 dark:text-gray-200">{i}</td>
                            <td class="px-4 py-3 text-sm break-all break-words max-w-[400px]"><a href="{url_escaped}" target="_blank" class="text-blue-600 dark:text-blue-400 hover:underline">{url_escaped}</a></td>
                        </tr>
"""
            html_output += """
                    </tbody>
                </table>
            </div>
        </div>
"""

    html_output += """
        <script>
        function openTab(evt, tabName) {
            var tabcontent = document.getElementsByClassName("tabcontent");
            for (var i = 0; i < tabcontent.length; i++) {
                tabcontent[i].style.display = "none";
            }
            var tablinks = document.getElementsByClassName("tablinks");
            for (var i = 0; i < tablinks.length; i++) {
                tablinks[i].className = tablinks[i].className.replace(" active", "");
            }
            document.getElementById(tabName).style.display = "block";
            evt.currentTarget.className += " active";
        }

        document.addEventListener('DOMContentLoaded', function() {
            var scrollContainers = document.querySelectorAll('.scroll-container');
            scrollContainers.forEach(function(container) {
                if (container.scrollHeight > container.clientHeight) {
                    container.classList.add('border', 'border-gray-200', 'dark:border-gray-600');
                }
            });

            const themeToggle = document.getElementById('themeToggle');
            themeToggle.addEventListener('click', () => {
                document.documentElement.classList.toggle('dark');
                localStorage.setItem('theme', document.documentElement.classList.contains('dark') ? 'dark' : 'light');
            });

            if (localStorage.getItem('theme') === 'dark') {
                document.documentElement.classList.add('dark');
            }

            console.log('Screen width: ' + window.innerWidth + 'px');
            const container = document.querySelector('.container');
            console.log('Container width: ' + container.offsetWidth + 'px');

            const chartOptions = {
                scales: {
                    y: { beginAtZero: true }
                },
                plugins: {
                    legend: { display: false }
                },
                maintainAspectRatio: false
            };

            new Chart(document.getElementById('assetsChart'), {
                type: 'bar',
                data: {
                    labels: ['Total Assets', 'Live Assets', 'Application Endpoints'],
                    datasets: [{
                        label: 'Count',
                        data: [""" + str(unique_assets) + """, """ + str(live_assets) + """, """ + str(app_endpoints) + """],
                        backgroundColor: ['#3b82f6', '#10b981', '#ef4444']
                    }]
                },
                options: chartOptions
            });
"""

    if http_status_codes:
        html_output += """
            new Chart(document.getElementById('statusChart'), {
                type: 'bar',
                data: {
                    labels: """ + str(list(http_status_codes.keys())) + """,
                    datasets: [{
                        label: 'Count',
                        data: """ + str(list(http_status_codes.values())) + """,
                        backgroundColor: '#3b82f6'
                    }]
                },
                options: chartOptions
            });
"""

    if top_ports:
        html_output += """
            new Chart(document.getElementById('portsChart'), {
                type: 'bar',
                data: {
                    labels: """ + str(list(top_ports.keys())) + """,
                    datasets: [{
                        label: 'Count',
                        data: """ + str(list(top_ports.values())) + """,
                        backgroundColor: '#10b981'
                    }]
                },
                options: chartOptions
            });
"""

    if top_tech:
        html_output += """
            new Chart(document.getElementById('techChart'), {
                type: 'bar',
                data: {
                    labels: """ + str(list(top_tech.keys())) + """,
                    datasets: [{
                        label: 'Count',
                        data: """ + str(list(top_tech.values())) + """,
                        backgroundColor: '#ef4444'
                    }]
                },
                options: chartOptions
            });
"""

    html_output += """
            new Chart(document.getElementById('urlsChart'), {
                type: 'bar',
                data: {
                    labels: ['URLs Found'],
                    datasets: [{
                        label: 'Count',
                        data: [""" + str(urls_found) + """],
                        backgroundColor: '#8b5cf6'
                    }]
                },
                options: chartOptions
            });
        });
        </script>
"""

    current_date = datetime.now().strftime("%d.%m.%Y %H:%M")
    html_output += """
        <footer class="mt-8 text-center text-gray-600 dark:text-gray-400 text-sm">
            Report generated: """ + current_date + """
        </footer>
    </div>
</body>
</html>
"""
    return html_output

def main():
    if len(sys.argv) != 2:
        print("Usage: python nuclei_with_cookiemonster.py input_file.txt")
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
        
        cookiemonster_file = os.path.join(base_dir, "cookiemonster.txt")
        cookiemonster_results = parse_cookiemonster_file(cookiemonster_file)
        if cookiemonster_results:
            additional_files["cookiemonster"] = cookiemonster_results
        
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
