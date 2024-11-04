# script to populate the TAXII DB with STIX data

import json
import os
from stix2 import (
    Indicator,
    Bundle,
    IPv4Address,
    URL,
    DomainName,
    Relationship,
    File,
    TLP_WHITE,
    TLP_RED
)
from taxii2client.v21 import Server
from dotenv import load_dotenv

# load environment variables from .env file
load_dotenv()

# retrieve TAXII server configuration from environment variables
TAXII_SERVER = os.getenv("TAXII_SERVER")
COLLECTION_ALIAS = os.getenv("COLLECTION_ALIAS")
USERNAME = os.getenv("USERNAME", "admin")
PASSWORD = os.getenv("PASSWORD", "admin")

def poppulate():
    # connect to the TAXII server using provided credentials
    server = Server(
        url=TAXII_SERVER,
        user=USERNAME,
        password=PASSWORD
    )
    
    # get the default API root from the TAXII server
    api_roots = server.api_roots
    api_root = api_roots[0]
    
    # find the collection to post the STIX objects to
    collection_to_post = None
    for collection in api_root.collections:
        if collection.alias == COLLECTION_ALIAS:
            collection_to_post = collection
            break
    
    if collection_to_post is None:
        raise Exception(f"Collection '{COLLECTION_ALIAS}' not found")
    
    # set the Traffic Light Protocol (TLP) marking
    tlp_marking_white = TLP_WHITE
    tlp_marking_red = TLP_RED
    
    # create an IPv4 address object
    ip_v4 = IPv4Address(
        value='1.1.1.20',
        object_marking_refs=tlp_marking_white
    )
    
    # create a URL object
    url = URL(
        value='http://malicious-site.com',
        object_marking_refs=tlp_marking_red
    )
    
    # create a hash indicator
    hash_indicator = Indicator(
        name="Malicious Hash",
        description="This hash is associated with malware",
        labels=["malicious-activity"],
        pattern="[file:hashes.'SHA-256' = 'ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c']",
        pattern_type="stix",
        confidence=80,
        object_marking_refs=tlp_marking_white
    )
    
    # create a domain name object
    domain_name = DomainName(
        value='malicious.com',
        object_marking_refs=tlp_marking_white
    )
    
    ip_v4_2 = IPv4Address(
        value='1.1.1.21',
        object_marking_refs=tlp_marking_white
    )

    # file
    file = File(
        name='malware.exe',
        hashes={
            'SHA-256': 'ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6b'
        },
        object_marking_refs=tlp_marking_white
    )

    # create a relationship between the IP and domain name
    relationship = Relationship(
        source_ref=ip_v4_2.id,
        target_ref=domain_name.id,
        relationship_type="related-to"
    )
    
    # create bundles
    bundles = [
        Bundle(objects=[ip_v4, tlp_marking_white]),
        Bundle(objects=[url, tlp_marking_red]),
        Bundle(objects=[hash_indicator, tlp_marking_white]),
        Bundle(objects=[ip_v4_2, domain_name, relationship, tlp_marking_white]),
        Bundle(objects=[file, tlp_marking_white])
    ]
    
    # post each bundle to the TAXII collection
    for bundle in bundles:
        serialized_bundle = bundle.serialize(pretty=True)
        response = collection_to_post.add_objects(serialized_bundle)
        print("Response Status from TAXII Server:")
        print(response.status)
        print(f"Response custom props:\n {response.custom_properties}")
        print('Done')

poppulate()

