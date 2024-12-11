import requests
import validators
import os
from dotenv import load_dotenv

# Load API key from .env file
load_dotenv()
API_KEY = os.getenv("SAFE_BROWSING_API_KEY")

def check_url_safety(url):
    if not validators.url(url):
        return {"error": "Invalid URL"}

    api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    headers = {"Content-Type": "application/json"}
    payload = {
        "client": {
            "clientId": "your-app-name",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    response = requests.post(api_url, json=payload, params={"key": API_KEY}, headers=headers)

    if response.status_code == 200:
        result = response.json()
        if "matches" in result:
            return {"url": url, "status": "unsafe", "details": result["matches"]}
        else:
            return {"url": url, "status": "safe"}
    else:
        return {"error": f"API request failed with status code {response.status_code}"}

# Example usage
if __name__ == "__main__":
    url_to_check = input("Enter a URL to scan: ").strip()
    result = check_url_safety(url_to_check)
    print(result)
