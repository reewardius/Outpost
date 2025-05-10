# Prompts
**Prompt 1: Comprehensive Report Analysis**
```
As a professional pentester, I need you to analyze the attached pentest report [attach report or paste content]. Please perform the following:
1. Summarize the key findings, including the total number of vulnerabilities by severity (Critical, High, Medium, Low, Info).
2. Identify and validate all vulnerabilities with provided PoCs, focusing on Critical and High-severity issues. For each validated vulnerability, provide:
   - Description of the vulnerability.
   - PoC steps to reproduce.
   - Potential impact (e.g., data breach, system compromise).
   - Remediation recommendations.
3. Filter out potential false positives, especially in Medium and Low-severity categories, and explain why they may not be exploitable.
4. Analyze any additional findings (e.g., Ffuf results, exposed files, or misconfigurations) and assess their significance.
5. Provide a prioritized list of vulnerabilities to address, with a clear explanation of why certain issues are more urgent.
6. Include general security recommendations to prevent similar issues in the future (e.g., secure coding practices, server hardening).
7. If any vulnerabilities require further investigation (e.g., fuzzing-based results), suggest specific manual testing steps.
Ensure the response is professional, concise, and actionable, formatted in a clear structure (e.g., tables, bullet points).
```
**Prompt 2: Focused Critical and High-Severity Analysis**
```
I am a pentester analyzing a pentest report [attach report or paste content]. Please focus on Critical and High-severity vulnerabilities and perform the following:
1. List all Critical and High-severity vulnerabilities with their details (e.g., CVE/Template, URL, protocol, method).
2. Validate each vulnerability with the provided PoC, confirming exploitability. Provide:
   - Step-by-step PoC reproduction instructions.
   - Potential impact of exploitation.
   - Specific remediation steps.
3. Prioritize these vulnerabilities based on their exploitability and potential impact (e.g., likelihood of remote code execution, data exposure).
4. Suggest immediate mitigation actions to reduce risk until full remediation is implemented.
5. If any vulnerabilities appear ambiguous or require manual verification, provide guidance on how to confirm them.
Keep the response concise, professional, and formatted for quick reference (e.g., tables or numbered lists).
```
**Prompt 3: False Positive Filtering and Validation**
```
As a pentester, I need you to analyze the attached pentest report [attach report or paste content] with a focus on filtering false positives. Please:
1. Review all vulnerabilities, paying special attention to Medium and Low-severity issues, as well as fuzzing-based results (e.g., XSS fuzzing, CRLF injection).
2. Identify potential false positives and explain why they may not be exploitable (e.g., lack of impact, incorrect context, or WAF protection).
3. Validate true positives with provided PoCs, providing:
   - Clear reproduction steps.
   - Impact assessment.
   - Remediation recommendations.
4. Summarize the confirmed vulnerabilities in a table, categorized by severity.
5. Provide guidance on manual testing for any ambiguous vulnerabilities to confirm their validity.
6. Include recommendations for improving scanning configurations to reduce false positives in future reports.
Ensure the response is clear, professional, and structured for easy review.
```
**Prompt 4: Specific Vulnerability Deep Dive**
```
I am a pentester analyzing a pentest report [attach report or paste content]. Please perform a deep dive into [specify vulnerability type, e.g., XSS, SSRF, LFI] vulnerabilities and provide:
1. A list of all instances of [vulnerability type] in the report, including severity, URL, protocol, and method.
2. Validation of each instance with the provided PoC, including:
   - Step-by-step reproduction instructions.
   - Assessment of real-world exploitability (e.g., prerequisites, limitations).
   - Potential impact (e.g., data theft, privilege escalation).
3. Detailed remediation steps specific to [vulnerability type], including code-level fixes, server configurations, or policy changes.
4. Recommendations for preventing [vulnerability type] in the future (e.g., secure coding practices, input validation).
5. If any instances are likely false positives, explain why and suggest manual verification steps.
Format the response professionally with clear sections and actionable insights.
```
**Prompt 5: Ffuf Findings and Exposed Resource Analysis**
```
As a pentester, I need you to analyze the Ffuf findings in the attached pentest report [attach report or paste content]. Please:
1. List all discovered URLs or resources (e.g., files, directories, endpoints) and their potential significance.
2. Validate each finding to determine if it exposes sensitive information (e.g., configuration files, source code, admin panels).
3. For each significant finding, provide:
   - Description of the resource and its potential risk (e.g., data leakage, unauthorized access).
   - Steps to confirm the exposure (e.g., HTTP request, authentication checks).
   - Remediation recommendations (e.g., access restrictions, file removal).
4. Identify any findings that are likely low-risk or irrelevant and explain why.
5. Suggest additional manual tests to uncover related vulnerabilities (e.g., brute-forcing, privilege escalation).
6. Provide general recommendations for securing exposed resources (e.g., .htaccess, WAF rules).
Ensure the response is professional, concise, and formatted for clarity (e.g., tables, bullet points).
```
**Prompt 6: Report Comparison and Trend Analysis**
```
I am a pentester analyzing multiple pentest reports [attach reports or paste content]. Please perform a comparative analysis and:
1. Summarize the vulnerabilities found in each report, categorized by severity (Critical, High, Medium, Low, Info).
2. Identify recurring vulnerabilities across reports (e.g., XSS, misconfigurations) and assess their persistence.
3. Validate recurring vulnerabilities with provided PoCs, providing:
   - Reproduction steps.
   - Impact assessment.
   - Remediation recommendations.
4. Highlight any new vulnerabilities introduced in the latest report compared to previous ones.
5. Analyze trends (e.g., increasing XSS issues, improved patching) and suggest root causes (e.g., lack of input validation, outdated software).
6. Provide strategic recommendations to address recurring issues and prevent future vulnerabilities (e.g., developer training, CI/CD security checks).
Format the response professionally with clear comparisons (e.g., tables, charts if applicable) and actionable insights.
```
**Prompt 7: Remediation Plan Development**
```
As a pentester, I need you to analyze the attached pentest report [attach report or paste content] and develop a remediation plan. Please:
1. List all confirmed vulnerabilities, prioritized by severity (Critical, High, Medium, Low).
2. For each vulnerability, provide:
   - A brief description and its impact.
   - Specific remediation steps (e.g., code changes, server configurations, policy updates).
   - Estimated effort (e.g., low, medium, high) and timeline for remediation.
3. Suggest temporary mitigation measures for Critical and High-severity issues to reduce risk immediately.
4. Group remediation steps by category (e.g., application fixes, server hardening, policy changes) for easier implementation.
5. Provide general security best practices to prevent similar vulnerabilities in the future (e.g., secure SDLC, regular pentests).
6. Include a prioritized action plan with clear steps and responsibilities (e.g., developers, sysadmins).
Ensure the response is professional, actionable, and formatted as a remediation plan (e.g., tables, numbered steps).
```
