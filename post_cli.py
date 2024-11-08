#!/usr/bin/env python3

import json
import os
import argparse
from stix2 import (
    Indicator,
    Bundle,
    IPv4Address,
    URL,
    DomainName,
    File,
    TLP_WHITE,
    TLP_AMBER,
    TLP_RED,
    TLP_GREEN
)
from taxii2client.v21 import Server
from dotenv import load_dotenv

def main():
    # Load environment variables from .env file
    load_dotenv()

    # Retrieve TAXII server configuration from environment variables
    TAXII_SERVER = os.getenv("TAXII_SERVER")
    COLLECTION_ALIAS = os.getenv("COLLECTION_ALIAS")
    USERNAME = os.getenv("USERNAME", "admin")
    PASSWORD = os.getenv("PASSWORD", "admin")

    # Argument parser setup
    parser = argparse.ArgumentParser(description='Post STIX objects to a TAXII server.')
    parser.add_argument('-t', '--type', required=True, choices=['ipv4-addr', 'url', 'domain-name', 'file'], help='Type of STIX object to create')
    parser.add_argument('-v', '--value', required=True, help='Value of the STIX object')
    parser.add_argument('-tlp', '--tlp', default='white', choices=['white', 'green', 'amber', 'red'], help='Traffic Light Protocol (TLP) marking')
    args = parser.parse_args()

    # Set TLP marking based on argument
    tlp_marking = {
        'white': TLP_WHITE,
        'green': TLP_GREEN,
        'amber': TLP_AMBER,
        'red': TLP_RED
    }[args.tlp]

    # Create the STIX object based on type
    if args.type == 'ipv4-addr':
        stix_object = IPv4Address(
            value=args.value,
            object_marking_refs=tlp_marking
        )

    elif args.type == 'url':
        stix_object = URL(
            value=args.value,
            object_marking_refs=tlp_marking
        )

    elif args.type == 'domain-name':
        stix_object = DomainName(
            value=args.value,
            object_marking_refs=tlp_marking
        )

    elif args.type == 'file':
        stix_object = File(
            hashes={
                'SHA-256': args.value
            },
            object_marking_refs=tlp_marking
        )

    else:
        print(f"Unsupported STIX object type: {args.type}")
        return

    # Create a Bundle object and add the STIX object to it
    bundle = Bundle(objects=[stix_object, tlp_marking])

    # Serialize the bundle to a JSON-formatted string
    serialized_bundle = bundle.serialize(pretty=True)
    print("Serialized Bundle:\n----------------")
    print(serialized_bundle)

    # Connect to the TAXII server using provided credentials
    server = Server(
        url=TAXII_SERVER,
        user=USERNAME,
        password=PASSWORD
    )
    print("\nConnected to TAXII Server:")
    print(f"Server: {TAXII_SERVER}")
    print(f"Username: {USERNAME}")
    print(f"Collection Alias: {COLLECTION_ALIAS}")

    # Get the default API root from the TAXII server
    api_roots = server.api_roots
    api_root = api_roots[0]
    print("\nAvailable API Roots:")
    for root in api_roots:
        print(f"- {root.url}")

    # Find the collection to post the STIX objects to
    collection_to_post = None
    for collection in api_root.collections:
        if collection.alias == COLLECTION_ALIAS:
            collection_to_post = collection
            break

    if collection_to_post is None:
        raise Exception(f"Collection '{COLLECTION_ALIAS}' not found")

    print(f"\nPosting to Collection: {collection_to_post.title}")

    # Post the bundle to the TAXII collection
    response = collection_to_post.add_objects(serialized_bundle)
    print("Response Status from TAXII Server:")
    print(response.status)
    print(f"Response custom props:\n {response.custom_properties}")

if __name__ == "__main__":
    main()
