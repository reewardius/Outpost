# Palka-Kopalka-1337

🔎 A tool for reconnaissance, bruteforce, vulnerability scanning, misconfiguration detection, and secret leakage discovery in web and network services, with handy report generation for further analysis.

## Install ProjectDiscovery Tools and Templates:

```bash
go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest && pdtm -install-all
go install github.com/projectdiscovery/katana/cmd/katana@v1.1.0
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
- Fast scanning using custom Nuclei templates.
- Includes templates for FUZZ testing (DAST).
- Report generation for deeper analysis.
