import requests
from bs4 import BeautifulSoup

def get_test_data():
    url = "https://www.virustotal.com/gui/home/upload" #test website
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)
        soup = BeautifulSoup(response.content, 'html.parser')
        print(soup.title) #print the title of the website.
        return soup
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data: {e}")
        return None

if __name__ == "__main__":
    test_data = get_test_data()
    if test_data:
        print("Data fetched successfully!")
