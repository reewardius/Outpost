# Outpost

🔎 A tool for reconnaissance, bruteforce, vulnerability scanning, misconfiguration detection, and secret leakage discovery in web and network services, with handy report generation for further analysis.

## **Requirements:**

- Golang (for installing pdtm tools)
- Python3
- Bash
- Linux or WSL

## Install ProjectDiscovery Tools and Templates:

```bash
go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest && pdtm -install-all
go install github.com/projectdiscovery/katana/cmd/katana@v1.1.0
go install -v github.com/sa7mon/s3scanner@latest
go install github.com/003random/getJS/v2@latest
go install github.com/ffuf/ffuf/v2@latest
python3 -m pip install --user pipx && python3 -m pipx ensurepath && pipx install uro
git clone https://github.com/reewardius/palka-kopalka-1337 && cd palka-kopalka-1337
git clone https://github.com/reewardius/nuclei-fast-templates
git clone https://github.com/reewardius/nuclei-dast-templates
```

## Run:
You can run the script in two ways:

**1. Using a file with root domains**

Create a file (e.g., root.txt) and add your target domains, one per line:
```bash
nano root.txt   # Add root domains for scanning
```
Then run the script like this:
```bash
bash general_easm.sh -f root.txt
```
**2. Using a single domain directly**

You can also scan a single domain:
```bash
bash general_easm.sh -d target.com
```
---

## Features:
- Domain and network services reconnaissance.
- Vulnerability, misconfiguration and secrets scanning.
- Fast scanning using default and custom Nuclei templates.
- Includes templates for FUZZ testing (DAST).
- Report generation for deeper analysis (example report: `general_report.html`).
