from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.common.exceptions import NoSuchElementException, WebDriverException
import time

# Function to find hidden client-side pages using Selenium
def find_hidden_pages(driver, base_url, wordlist_file):
    try:
        # Load the wordlist of client-side routes
        with open(wordlist_file, "r") as file:
            routes = file.readlines()

        hidden_pages = []

        for route in routes:
            route = route.strip()  # Remove any trailing whitespace
            full_url = f"{base_url}#/{route}"

            try:
                # Navigate to the potential client-side route
                driver.get(full_url)
                time.sleep(2)  # Wait for the page to load (can adjust based on web app speed)

                # Check if the page changed (for example, checking if a unique element exists)
                # This can be customized to check for specific elements, page titles, etc.
                try:
                    body_content = driver.find_element(By.TAG_NAME, "body").text
                    if body_content and route not in hidden_pages:
                        hidden_pages.append(full_url)
                except NoSuchElementException:
                    pass  # If no body content found, skip this route

            except WebDriverException as e:
                print(f"Error navigating to {full_url}: {e}")

        return hidden_pages

    except FileNotFoundError:
        print(f"Wordlist file '{wordlist_file}' not found.")
        return []

# Example usage (this part is for testing purposes, you can call this from your main script)
if __name__ == "__main__":
    base_url = "http://localhost:42000/"
    wordlist_file = "common_paths.txt"  # The text file with possible hidden client-side routes

    # Initialize the Selenium WebDriver (Firefox in this case)
    driver = webdriver.Firefox()

    try:
        found_pages = find_hidden_pages(driver, base_url, wordlist_file)

        print("Hidden client-side pages found:")
        for page in found_pages:
            print(page)
    finally:
        driver.quit()
