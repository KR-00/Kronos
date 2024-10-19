import socket

def get_ip_address(url):
    try:
        # Get the IP address by using the gethostbyname() method
        ip_address = socket.gethostbyname(url)
        return ip_address
    except socket.gaierror:
        return "Error: Unable to resolve the URL."

if __name__ == "__main__":
    # Prompt the user to enter a URL
    url = input("Enter the URL (e.g., example.com): ")
    ip = get_ip_address(url)
    print(f"The IP address of {url} is: {ip}")