# Palka-Kopalka-1337

🔎 A tool for reconnaissance, bruteforce, vulnerability scanning, misconfiguration detection, and secret leakage discovery in web and network services, with handy report generation for further analysis.

## **Requirements:**

- Golang (for installing pdtm tools)
- Bash
- Linux or WSL

## Install ProjectDiscovery Tools and Templates:

```bash
go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest && pdtm -install-all
go install github.com/projectdiscovery/katana/cmd/katana@v1.1.0
go install github.com/003random/getJS/v2@latest
pipx install uro
git clone https://github.com/reewardius/palka-kopalka-1337 && cd palka-kopalka-1337
git clone https://github.com/reewardius/nuclei-fast-templates
git clone https://github.com/reewardius/nuclei-dast-templates
```

## Run:

```bash
nano root.txt   # Add root domains for scanning
chmod +x general_easm.sh && bash general_easm.sh
```

---

## Features:
- Domain and network services reconnaissance.
- Vulnerability, misconfiguration and secrets scanning.
- Fast scanning using default and custom Nuclei templates.
- Includes templates for FUZZ testing (DAST).
- Report generation for deeper analysis (example report: `general_report.html`).
