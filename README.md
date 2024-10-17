# Basic Posting STIX Objects to a TAXII Server

This script demonstrates how to create STIX objects and post them to a TAXII 2.1 server using Python.

## Overview

- **STIX2**: Structured Threat Information Expression, a standardized language for sharing cyber threat intelligence.
- **TAXII**: Trusted Automated Exchange of Intelligence Information, a protocol for exchanging CTI over HTTPS.

## Prerequisites

- **Python 3.6+**
- **TAXII 2.1 Server**: An accessible TAXII server instance (e.g., [OpenTAXII](https://github.com/eclecticiq/OpenTAXII)).

## Setup

1. **Clone the Repository**

   ```bash
   git clone https://github.com/n45os/basic-STIX-poster.git
   cd basic-STIX-poster 
   ```

2. **Install Dependencies (recommended to run it in a python venv)**

   ```bash
    pip install -r requirements.txt
    ```

3. **Run the Script**

   ```bash
   python post.py
   ```
