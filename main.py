from selenium import webdriver

# Function to prompt for port and handle invalid inputs
def get_port():
    while True:
        port = input("Please enter the port Juice Shop is running on (default is 42000): ")

        if not port:
            # Default to 3000 if no input is provided
            return 42000
        try:
            # Try to convert input to an integer (valid port number)
            return int(port)
        except ValueError:
            # Handle invalid input
            print("Invalid input. Please enter a valid port number.")

# Get the port from the user
port = get_port()

# Create the base URL for Juice Shop
juice_shop_url = f"http://localhost:{port}"

# Set up Selenium WebDriver for Firefox
driver = webdriver.Firefox()

# Open Juice Shop at the specified port
driver.get(juice_shop_url)

# Print the page title to verify that Selenium is working
print(f"Page title: {driver.title}")

# Close the browser
driver.quit()
