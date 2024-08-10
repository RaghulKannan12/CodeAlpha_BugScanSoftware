Python script creates a simple graphical user interface (GUI) application for performing basic web vulnerability assessments using the tkinter library for the GUI and requests for making HTTP requests. Here's a detailed description of the code:

Overview
The BugHuntingTool class sets up a Tkinter-based GUI to scan a specified URL for various common web vulnerabilities. The tool performs the following checks:

SQL Injection: Tests for SQL injection vulnerabilities.
Cross-Site Scripting (XSS): Tests for XSS vulnerabilities.
Sensitive Data Exposure: Checks for common sensitive files.
Security Misconfiguration: Checks for default admin pages.
Broken Authentication: Checks for broken authentication endpoints.
Insecure Deserialization: Tests for insecure deserialization.
Components with Known Vulnerabilities: Checks for outdated components.
Insufficient Logging and Monitoring: Tests for common logging paths.
Broken Access Control: Checks for unauthorized access to restricted pages.
XML External Entities (XXE): Tests for XXE vulnerabilities.
