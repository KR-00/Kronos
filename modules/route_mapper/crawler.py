# modules/route_mapper/crawler.py

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.common.exceptions import NoSuchElementException, WebDriverException
import time
import re

# Function to check if the current page is unique by checking page content
def is_unique_page(driver, unique_pages, url):
    time.sleep(2)

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

        if '/redirect' in current_url:
            continue
        if re.search(r'legal\.md$', current_url):
            continue

        try:
            driver.get(current_url)

            if not current_url.startswith(base_url):
                continue
            if re.search(r'\.(pdf|md|jpg|png|zip|gif|jpeg|exe|doc|docx|txt)$', current_url):
                continue

            if is_unique_page(driver, unique_pages, current_url):
                discovered_urls.append(current_url)

                links = driver.find_elements(By.TAG_NAME, "a")
                for link in links:
                    href = link.get_attribute("href")
                    if href and href.startswith(base_url) and href not in discovered_urls and href not in pages_to_check:
                        pages_to_check.append(href)

        except WebDriverException as e:
            continue

    return discovered_urls

# Updated start_crawler function to return the discovered pages
def start_crawler(port):
    """ Entry point for running the crawler with the given port """
    juice_shop_url = f"http://localhost:{port}"
    driver = webdriver.Firefox()
    discovered_pages = []
    try:
        driver.get(juice_shop_url)
        discovered_pages = discover_pages(driver, juice_shop_url)
    except Exception as e:
        discovered_pages.append(f"An error occurred: {e}")
    finally:
        driver.quit()
    
    return discovered_pages  # Return the list of discovered pages
