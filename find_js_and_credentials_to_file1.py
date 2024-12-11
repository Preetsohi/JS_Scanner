import requests
from bs4 import BeautifulSoup
import urllib.parse
import re
import csv

# List of keywords to search for in the JS files
keywords = [
    'production', 'environment', 'username', 'password', 'client_id', 'client_secret', 
    'profile_s3_path', 's3_path', 'grant_type', 'address_lookup_key', 'magentoApiUrl', 
    'magentoApiVersion', 'yourAccessKeyId', 'yourSecretAccessKey', 'yourBucketName', 
    'profileFolder', 'cmsNavigationUrl', 'graphcmsapiurl', 'qraphapiToken', 
    'versionCheckURL', 'Token', 'secret_key', 'hashedSecretKey', 'hashedIV', 
    'recaptchaSecretKey', 'recaptchasiteKey'
]

# Function to search for keywords and capture their values in a text string
def search_keywords_in_text(text, keywords):
    found_keywords = {}
    for keyword in keywords:
        # Regular expression to match the keyword and its associated value
        # Matches patterns like: username = 'value'; or password:"secret"
        pattern = re.compile(r'\b' + re.escape(keyword) + r'\s*[:=]\s*["\']?([^"\']+)["\']?', re.IGNORECASE)
        matches = pattern.findall(text)
        if matches:
            found_keywords[keyword] = matches
    return found_keywords

# Function to extract JS files from a URL
def find_js_files(url):
    response = requests.get(url)
    if response.status_code != 200:
        print(f"Failed to retrieve {url}")
        return []

    # Parse the HTML content
    soup = BeautifulSoup(response.text, 'html.parser')

    # Find all <script> tags with 'src' attribute
    js_files = []
    for script in soup.find_all('script', src=True):
        js_url = script['src']
        
        # If the js_url is relative, resolve it
        js_url = urllib.parse.urljoin(url, js_url)
        js_files.append(js_url)

    return js_files

# Function to download and search a JS file for keywords
def search_js_file_for_keywords(js_file_url, keywords):
    print(f"Scanning {js_file_url} for sensitive keywords...")
    response = requests.get(js_file_url)

    if response.status_code != 200:
        print(f"Failed to download {js_file_url}")
        return {}

    js_text = response.text
    found_keywords = search_keywords_in_text(js_text, keywords)

    return found_keywords

# Function to ensure URL has a valid scheme (https://)
def ensure_valid_url(url):
    # Check if the URL has a scheme (http:// or https://)
    parsed_url = urllib.parse.urlparse(url)
    if not parsed_url.scheme:
        # If no scheme is provided, assume https
        url = 'https://' + url
    return url

# Function to write the results to a .csv file
def write_results_to_csv(results, filename="found_credentials.csv"):
    with open(filename, mode='w', newline='', encoding='utf-8') as file:
        csv_writer = csv.writer(file)
        # Write the header row
        csv_writer.writerow(["JS File URL", "Keyword", "Value"])

        # Write the results
        for js_file_url, data in results.items():
            for keyword, values in data.items():
                for value in values:
                    csv_writer.writerow([js_file_url, keyword, value])
    print(f"Results written to {filename}")

# Main function
def main():
    url = input("Enter the URL to crawl: ")

    # Ensure the URL is well-formed
    url = ensure_valid_url(url)

    # Step 1: Find all JavaScript files on the page
    js_files = find_js_files(url)
    if not js_files:
        print("No JavaScript files found.")
        return

    # Step 2: Check each JS file for the keywords
    sensitive_data_found = False
    results = {}

    for js_file_url in js_files:
        found_keywords = search_js_file_for_keywords(js_file_url, keywords)
        if found_keywords:
            results[js_file_url] = found_keywords
            sensitive_data_found = True

    if sensitive_data_found:
        write_results_to_csv(results)
    else:
        print("No sensitive data found in the JS files.")

if __name__ == "__main__":
    main()
