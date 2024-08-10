import tkinter as tk
from tkinter import messagebox
import requests
import threading
import re

class BugHuntingTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Bug Hunting Tool")

        # Create and place widgets
        self.url_label = tk.Label(root, text="Target URL:")
        self.url_label.pack(pady=5)

        self.url_entry = tk.Entry(root, width=50)
        self.url_entry.pack(pady=5)

        self.scan_button = tk.Button(root, text="Start Scan", command=self.start_scan)
        self.scan_button.pack(pady=20)

        self.results_text = tk.Text(root, height=20, width=80)
        self.results_text.pack(pady=5)

    def start_scan(self):
        url = self.url_entry.get()
        if not url:
            messagebox.showwarning("Input Error", "Please enter a target URL.")
            return

        self.results_text.delete(1.0, tk.END)  # Clear previous results
        self.scan_button.config(state=tk.DISABLED)  # Disable button during scan

        # Run the scan in a separate thread
        threading.Thread(target=self.perform_scan, args=(url,)).start()

    def perform_scan(self, url):
        self.results_text.insert(tk.END, "Starting vulnerability assessment...\n")

        # Run individual tests
        self.test_sql_injection(url)
        self.test_xss(url)
        self.test_sensitive_data_exposure(url)
        self.test_security_misconfiguration(url)
        self.test_broken_authentication(url)
        self.test_insecure_deserialization(url)
        self.test_using_components_with_known_vulnerabilities(url)
        self.test_insufficient_logging_and_monitoring(url)
        self.test_broken_access_control(url)
        self.test_xml_external_entities(url)

        self.results_text.insert(tk.END, "\nAssessment completed.")
        self.scan_button.config(state=tk.NORMAL)  # Re-enable the button

    def test_sql_injection(self, url):
        payloads = ["' OR '1'='1", "' OR 1=1--", '" OR "1"="1']
        for payload in payloads:
            test_url = f"{url}?id={payload}"
            try:
                response = requests.get(test_url)
                if "syntax error" in response.text or "SQL" in response.text:
                    self.results_text.insert(tk.END, f"SQL Injection vulnerability detected at {test_url}\n")
            except Exception as e:
                self.results_text.insert(tk.END, f"Error testing {test_url}: {str(e)}\n")

    def test_xss(self, url):
        payload = "<script>alert('XSS')</script>"
        test_url = f"{url}?search={payload}"
        try:
            response = requests.get(test_url)
            if payload in response.text:
                self.results_text.insert(tk.END, f"XSS vulnerability detected at {test_url}\n")
        except Exception as e:
            self.results_text.insert(tk.END, f"Error testing {test_url}: {str(e)}\n")

    def test_sensitive_data_exposure(self, url):
        sensitive_files = ["/.env", "/config.php", "/admin"]
        for file in sensitive_files:
            test_url = url + file
            try:
                response = requests.get(test_url)
                if response.status_code == 200:
                    self.results_text.insert(tk.END, f"Sensitive data exposure detected at {test_url}\n")
            except Exception as e:
                self.results_text.insert(tk.END, f"Error testing {test_url}: {str(e)}\n")

    def test_security_misconfiguration(self, url):
        default_admin_pages = ["/admin", "/administrator", "/admin/login"]
        for page in default_admin_pages:
            test_url = url + page
            try:
                response = requests.get(test_url)
                if response.status_code == 200:
                    self.results_text.insert(tk.END, f"Potential security misconfiguration detected at {test_url}\n")
            except Exception as e:
                self.results_text.insert(tk.END, f"Error testing {test_url}: {str(e)}\n")

    def test_broken_authentication(self, url):
        # This is a simplified example. Real checks might involve automated login attempts or password guessing.
        test_urls = [f"{url}/login", f"{url}/admin"]
        for test_url in test_urls:
            try:
                response = requests.get(test_url)
                if response.status_code == 200 and "login" in response.text:
                    self.results_text.insert(tk.END, f"Broken Authentication potential issue at {test_url}\n")
            except Exception as e:
                self.results_text.insert(tk.END, f"Error testing {test_url}: {str(e)}\n")

    def test_insecure_deserialization(self, url):
        # This is a complex vulnerability and typically requires more specific testing.
        test_url = f"{url}/api/test"
        payload = {"data": "test"}
        try:
            response = requests.post(test_url, json=payload)
            if "error" in response.text:
                self.results_text.insert(tk.END, f"Insecure Deserialization potential issue at {test_url}\n")
        except Exception as e:
            self.results_text.insert(tk.END, f"Error testing {test_url}: {str(e)}\n")

    def test_using_components_with_known_vulnerabilities(self, url):
        # Simplified example: Check for outdated components via common headers.
        headers = {"User-Agent": "test-agent"}
        try:
            response = requests.get(url, headers=headers)
            if "component-version" in response.headers:
                self.results_text.insert(tk.END, f"Using Components with Known Vulnerabilities detected at {url}\n")
        except Exception as e:
            self.results_text.insert(tk.END, f"Error testing {url}: {str(e)}\n")

    def test_insufficient_logging_and_monitoring(self, url):
        # This usually requires more specific checks. Example: Checking for common logging paths.
        logging_paths = ["/logs", "/admin/logs"]
        for path in logging_paths:
            test_url = url + path
            try:
                response = requests.get(test_url)
                if response.status_code == 200:
                    self.results_text.insert(tk.END, f"Insufficient Logging & Monitoring potential issue at {test_url}\n")
            except Exception as e:
                self.results_text.insert(tk.END, f"Error testing {test_url}: {str(e)}\n")

    def test_broken_access_control(self, url):
        # Example: Check for unauthorized access to admin pages.
        restricted_pages = ["/admin", "/user/profile"]
        for page in restricted_pages:
            test_url = url + page
            try:
                response = requests.get(test_url)
                if response.status_code == 200:
                    self.results_text.insert(tk.END, f"Broken Access Control potential issue at {test_url}\n")
            except Exception as e:
                self.results_text.insert(tk.END, f"Error testing {test_url}: {str(e)}\n")

    def test_xml_external_entities(self, url):
        # Testing for XXE vulnerabilities would typically require more specialized payloads and processing.
        payload = """<?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE foo [ 
        <!ELEMENT foo ANY >
        <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
        <foo>&xxe;</foo>"""
        test_url = f"{url}/api/xml"
        try:
            response = requests.post(test_url, data=payload, headers={"Content-Type": "application/xml"})
            if "root" in response.text:
                self.results_text.insert(tk.END, f"XML External Entities (XXE) potential issue at {test_url}\n")
        except Exception as e:
            self.results_text.insert(tk.END, f"Error testing {test_url}: {str(e)}\n")

# Create the main window and run the application
root = tk.Tk()
app = BugHuntingTool(root)
root.mainloop()
