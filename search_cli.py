import json
import requests
import argparse

def main():
    parser = argparse.ArgumentParser(description='Search STIX objects via API.')
    parser.add_argument('-t', '--type', required=True, help='Type of the object (e.g., "url", "hashes")')
    parser.add_argument('-v', '--value', required=False, help='Value to search for (e.g., "example.com")')
    parser.add_argument('-c', '--collection-id', default='internal-cti-collection', help='Collection ID (optional)')
    parser.add_argument('-r', '--get-related', required=False, default=True, help='Get related objects (relationships and marking defs) (optional)')
    
    parser.add_argument('-u', '--url', default='http://localhost:80', help='URL of the API endpoint')

    args = parser.parse_args()

    # Define the base URL for the API
    base_url = f"{args.url}/search"

    # Define the query parameters
    params = {
        "type": args.type,
        "collection_id": args.collection_id  # optional, can be omitted
    }

    if args.value is not None:
        params["value"] = args.value

    if args.get_related is not None:
        params["get_related"] = args.get_related

    # Make the GET request to the /search endpoint
    response = requests.get(base_url, params=params, headers={"accept": "application/json"})

    # Check if the request was successful
    if response.status_code == 200:
        # Parse and print the JSON response
        stix_objects = response.json()
        print("STIX Objects Found:")
        print(json.dumps(stix_objects, indent=4))
    elif response.status_code == 400:
        print("Bad Request:", response.json().get("message"))
    elif response.status_code == 404:
        print("Not Found:", response.json().get("message"))
    else:
        print(f"Error: {response.status_code}")

if __name__ == '__main__':
    main()
