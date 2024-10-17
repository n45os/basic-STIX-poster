# post_stix_objects.py

import json
import os
from stix2 import (
    Indicator,
    Bundle,
    IPv4Address,
    URL,
    TLP_WHITE,
    TLP_AMBER,
    TLP_RED,
    TLP_GREEN
)
from taxii2client.v21 import Server
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Retrieve TAXII server configuration from environment variables
TAXII_SERVER = os.getenv("TAXII_SERVER")
COLLECTION_ALIAS = os.getenv("COLLECTION_ALIAS")
USERNAME = os.getenv("USERNAME", "admin")
PASSWORD = os.getenv("PASSWORD", "admin")

print(f"Posting to TAXII server at: {TAXII_SERVER}")

# Set the Traffic Light Protocol (TLP) marking
tlp_marking = TLP_WHITE

# Create an IPv4 address object with TLP marking
ip_v4 = IPv4Address(
    value='1.1.1.4',
    object_marking_refs=tlp_marking
)

# Create a URL object with TLP marking
url = URL(
    value='http://example.com',
    object_marking_refs=tlp_marking
)

# Create an Indicator object for the malicious IP with TLP marking
ip_indicator = Indicator(
    name="Malicious IP 2",
    description="This IP is malicious",
    labels=["malicious-activity"],
    pattern="[ipv4-addr:value = '1.1.1.4']",
    pattern_type="stix",
    confidence=80,
    object_marking_refs=tlp_marking
)

# Print the serialized STIX objects for verification
print("IP object:\n----------------")
print(ip_v4.serialize(pretty=True))

print("IP indicator:\n----------------")
print(ip_indicator.serialize(pretty=True))

print("URL object:\n----------------")
print(url.serialize(pretty=True))

# Create a Bundle object and add the STIX objects to it
bundle = Bundle(objects=[ip_v4, url, tlp_marking])

# Connect to the TAXII server using provided credentials
server = Server(
    url=TAXII_SERVER,
    user=USERNAME,
    password=PASSWORD
)
print("Connected to TAXII Server:")
print(server)

# Get the default API root from the TAXII server
api_roots = server.api_roots
api_root = api_roots[0]
print("Available API Roots:")
print(api_roots)

# Find the collection to post the STIX objects to
collection_to_post = None
for collection in api_root.collections:
    if collection.alias == COLLECTION_ALIAS:
        collection_to_post = collection
        break

if collection_to_post is None:
    raise Exception(f"Collection '{COLLECTION_ALIAS}' not found")

# Serialize the bundle to a JSON-formatted string
serialized_bundle = bundle.serialize(pretty=True)
print("Serialized Bundle:\n----------------")
print(serialized_bundle)

# Post the bundle to the TAXII collection
response = collection_to_post.add_objects(serialized_bundle)
print("Response Status from TAXII Server:")
print(response.status)
print()

print(f"Response custom props:\n {response.custom_properties}")

print('Done')
