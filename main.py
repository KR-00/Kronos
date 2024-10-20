from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.common.exceptions import NoSuchElementException
from selenium.common.exceptions import WebDriverException
import time
import re

# Function to prompt for port and handle invalid inputs
def get_port():
    while True:
        port = input("Please enter the port Juice Shop is running on (default is 42000): ")

        if not port:
            return 42000
        try:
            return int(port)
        except ValueError:
            print("Invalid input. Please enter a valid port number.")

# Function to check if the current page is unique by checking page content
def is_unique_page(driver, unique_pages, url):
    # Wait for the page to load
    time.sleep(2)

    # Get a unique element from the page to check (e.g., page title or specific element)
    try:
        page_content = driver.find_element(By.TAG_NAME, 'body').text
        if page_content not in unique_pages:
            unique_pages[page_content] = url  # Store the page content and URL
            return True
    except NoSuchElementException:
        pass
    return False

# Function to discover all pages in the web app, ignoring external URLs and non-HTML files
def discover_pages(driver, base_url):
    pages_to_check = [base_url]  # Start with the base URL
    unique_pages = {}  # Dictionary to track unique page content
    discovered_urls = []  # List of unique URLs to return

    while pages_to_check:
        current_url = pages_to_check.pop(0)
        
        # Skip known problematic patterns like '/redirect' to avoid loops
        if '/redirect' in current_url:
            print(f"Skipping potential redirect loop: {current_url}")
            continue

        # Skip URLs like 'legal.md' to prevent file downloads
        if re.search(r'legal\.md$', current_url):
            print(f"Skipping file download: {current_url}")
            continue

        try:
            driver.get(current_url)

            # Avoid external links by checking if the URL starts with the base URL (http://localhost)
            if not current_url.startswith(base_url):
                print(f"Ignoring external page: {current_url}")
                continue

            # Avoid non-HTML files by skipping URLs that match certain file extensions
            if re.search(r'\.(pdf|md|jpg|png|zip|gif|jpeg|exe|doc|docx|txt)$', current_url):
                print(f"Ignoring non-HTML file: {current_url}")
                continue

            if is_unique_page(driver, unique_pages, current_url):
                print(f"Discovered unique page: {current_url}")
                discovered_urls.append(current_url)

                # Find all links on the current page and add them to the list to check
                links = driver.find_elements(By.TAG_NAME, "a")
                for link in links:
                    href = link.get_attribute("href")
                    # Only add links that belong to the same domain (localhost) and are not already checked
                    if href and href.startswith(base_url) and href not in discovered_urls and href not in pages_to_check:
                        pages_to_check.append(href)
                    elif href and not href.startswith(base_url):
                        print(f"Skipping external link: {href}")

        except WebDriverException as e:
            print(f"Error navigating to {current_url}: {e}")
            continue  # Skip to the next URL in case of an error

    return discovered_urls

# Main part of the script
def main():
    # Get the port from the user
    port = get_port()

    # Create the base URL for Juice Shop
    juice_shop_url = f"http://localhost:{port}"

    # Set up Selenium WebDriver for Firefox
    driver = webdriver.Firefox()

    try:
        # Open Juice Shop at the specified port
        driver.get(juice_shop_url)

        # Discover all unique pages
        unique_pages = discover_pages(driver, juice_shop_url)

        print("\nUnique pages discovered:")
        for page in unique_pages:
            print(page)
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        # Ensure the browser closes after crawling
        driver.quit()
        print("Browser closed.")

if __name__ == "__main__":
    main()
