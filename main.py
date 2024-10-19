from selenium import webdriver
from selenium.webdriver.common.by import By
import time

# Initialize the Selenium WebDriver (for Chrome, in this case)
def init_webdriver():
    # Make sure to download and place the ChromeDriver in your PATH or specify its path here.
    driver = webdriver.Chrome(executable_path='/path/to/chromedriver')  # Update path accordingly
    return driver

# Crawl the website using Selenium to capture dynamically loaded content
def crawl_website_selenium(url):
    driver = init_webdriver()  # Initialize the WebDriver
    driver.get(url)  # Load the page
    time.sleep(3)  # Allow time for the page to fully load

    forms = driver.find_elements(By.TAG_NAME, "form")  # Find all form elements
    inputs = driver.find_elements(By.TAG_NAME, "input")  # Find all input elements

    form_details = []
    for form in forms:
        inputs_in_form = form.find_elements(By.TAG_NAME, "input")  # Get inputs within each form
        form_details.append({
            "form": form,
            "inputs": [input_field.get_attribute('name') for input_field in inputs_in_form]
        })
    
    driver.quit()  # Close the browser after the scan
    return forms, inputs, form_details

# Main function
def main():
    url = input("Enter the website URL: ").strip()
    
    if not is_valid_url(url):
        print("Invalid URL. Please try again.")
        return
    
    print(f"Scanning {url} for vulnerabilities...\n")
    
    # Use Selenium to crawl the website for forms and inputs
    forms, inputs, form_details = crawl_website_selenium(url)
    
    if not forms and not inputs:
        print(f"No forms or inputs found on {url}")
        return

    # Inform the user what was found on the page
    print(f"Found {len(forms)} form(s) and {len(inputs)} input field(s) on {url}.")
    
    for form_info in form_details:
        print(f"Form with {len(form_info['inputs'])} input(s): {form_info['inputs']}")

    # Proceed with vulnerability testing as before...
    # You can pass forms, inputs, etc., to the vulnerability tests for further processing.

if __name__ == "__main__":
    main()
