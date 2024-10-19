import requests
from bs4 import BeautifulSoup
import re
import urllib.parse

# Helper function to check if URL is valid
def is_valid_url(url):
    parsed_url = urllib.parse.urlparse(url)
    return all([parsed_url.scheme, parsed_url.netloc])

# Function to crawl the website and find input fields
def crawl_website(url):
    try:
        response = requests.get(url, timeout=10)  # Adding timeout for network requests
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            inputs = soup.find_all('input')
            if not forms and not inputs:
                print(f"No forms or inputs found on {url}")
            return forms, inputs
        else:
            print(f"Error: Received status code {response.status_code} for {url}")
            return None, None
    except requests.exceptions.Timeout:
        print(f"Error: Connection to {url} timed out.")
        return None, None
    except requests.exceptions.RequestException as e:
        print(f"Error: An error occurred while connecting to {url}: {e}")
        return None, None

# Basic SQL Injection testing function
def test_sql_injection(url, form=None, input_field=None):
    sql_payloads = ["' OR 1=1 --", "' OR 'a'='a", "' UNION SELECT NULL, NULL --"]
    results = []

    for payload in sql_payloads:
        injected_url = url + payload
        try:
            response = requests.get(injected_url, timeout=10)
            if any(error in response.text.lower() for error in ["mysql", "syntax", "sql", "query"]):
                results.append(f"SQL Injection vulnerability detected with payload: {payload}")
        except requests.exceptions.RequestException as e:
            print(f"Error: Failed to test SQL Injection on {injected_url}: {e}")
    
    if not results:
        print("No SQL Injection vulnerabilities found.")
    return results

# Basic XSS testing function
def test_xss(url, form=None, input_field=None):
    xss_payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
    results = []

    for payload in xss_payloads:
        injected_url = url + payload
        try:
            response = requests.get(injected_url, timeout=10)
            if payload in response.text:
                results.append(f"XSS vulnerability detected with payload: {payload}")
        except requests.exceptions.RequestException as e:
            print(f"Error: Failed to test XSS on {injected_url}: {e}")
    
    if not results:
        print("No XSS vulnerabilities found.")
    return results

# Directory Traversal testing function
def test_directory_traversal(url):
    traversal_payloads = ["../../etc/passwd", "../../../../etc/passwd"]
    results = []

    for payload in traversal_payloads:
        injected_url = url + payload
        try:
            response = requests.get(injected_url, timeout=10)
            if "root:x:" in response.text:
                results.append(f"Directory Traversal vulnerability detected with payload: {payload}")
        except requests.exceptions.RequestException as e:
            print(f"Error: Failed to test Directory Traversal on {injected_url}: {e}")
    
    if not results:
        print("No Directory Traversal vulnerabilities found.")
    return results

# Main function
def main():
    url = input("Enter the website URL: ").strip()
    
    if not is_valid_url(url):
        print("Invalid URL. Please try again.")
        return
    
    print(f"Scanning {url} for vulnerabilities...\n")
    
    # Crawl the website for forms and inputs
    forms, inputs = crawl_website(url)
    
    if forms is None and inputs is None:
        print("Failed to crawl the website.")
        return

    # Inform the user what was found on the page
    print(f"Found {len(forms)} form(s) and {len(inputs)} input field(s) on {url}.")

    # Testing for SQL Injection
    print("\n[+] Testing for SQL Injection...")
    sql_injection_results = test_sql_injection(url)
    for result in sql_injection_results:
        print(result)

    # Testing for XSS
    print("\n[+] Testing for XSS...")
    xss_results = test_xss(url)
    for result in xss_results:
        print(result)

    # Testing for Directory Traversal
    print("\n[+] Testing for Directory Traversal...")
    traversal_results = test_directory_traversal(url)
    for result in traversal_results:
        print(result)

    print("\nScanning completed.")

if __name__ == "__main__":
    main()
