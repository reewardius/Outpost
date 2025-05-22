# Outpost

🔎 A tool for reconnaissance, bruteforce, vulnerability scanning, misconfiguration detection, and secret leakage discovery in web and network services, with handy report generation for further analysis.

## **Requirements:**

- Golang
- Python3
- Bash
- Linux or WSL

## Install Tools and Download Nuclei Templates:

```bash
go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest && pdtm -install-all
go install -v github.com/projectdiscovery/katana/cmd/katana@v1.1.0
go install -v github.com/tomnomnom/anew@latest && go install github.com/tomnomnom/unfurl@latest
go install -v github.com/sa7mon/s3scanner@latest && go install github.com/003random/getJS/v2@latest
go install -v github.com/ffuf/ffuf/v2@latest
go install -v github.com/iangcarroll/cookiemonster/cmd/cookiemonster@latest
python3 -m pip install --user pipx && python3 -m pipx ensurepath && pipx install uro
git clone https://github.com/reewardius/Outpost && cd Outpost
git clone https://github.com/reewardius/nuclei-fast-templates && git clone https://github.com/reewardius/nuclei-dast-templates
```

# Usage

🔹 Scan a list of root domains (with subdomain enumeration):
```bash
bash general_easm.sh -f root.txt
```
🔹 Scan a list of root domains (without subdomain enumeration):
```bash
bash general_easm.sh -f root.txt -ds
```
🔹 Scan a single domain (with subdomain enumeration):
```bash
bash general_easm.sh -d example.com
```
🔹 Scan a single domain (without subdomain enumeration):
```bash
bash general_easm.sh -d example.com -ds
```

## 📄 Final Report

After the script completes, all findings are merged and summarized into a single file: `general_report.html`

This HTML file consolidates results from:

- Vulnerability scans (Nuclei)
- Subdomain takeovers
- JS secrets
- Fuzzing results
- Crawled endpoints
- S3 bucket checks
- and more...

📌 **Open `general_report.html` in your browser to review the full recon and scanning results in a human-readable format.**
