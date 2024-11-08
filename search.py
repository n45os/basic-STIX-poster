import json
import requests

# Define the base URL for the API
base_url = "http://localhost:5001/search"

# Define the query parameters
# params = {
#     "type": "url",
#     "value": "example.com",
#     "collection_id": "internal-cti-collection"  # optional, can be omitted
# }

params = {
    "type": "hashes",
    "value": "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6f",
    "collection_id": "internal-cti-collection"  # optional, can be omitted
}

# Make the GET request to the /search endpoint
response = requests.get(base_url, params=params, headers={"accept": "application/json"})

# Check if the request was successful
if response.status_code == 200:
    # Parse and print the JSON response
    stix_objects = response.json()
    print("STIX Objects Found:")
    #print pretty
    print(json.dumps(stix_objects, indent=4))
elif response.status_code == 400:
    print("Bad Request:", response.json().get("message"))
elif response.status_code == 404:
    print("Not Found:", response.json().get("message"))
else:
    print(f"Error: {response.status_code}")
