import os
import csv
import time
from tenable.io import TenableIO
from dotenv import load_dotenv # Import load_dotenv

load_dotenv() # Load environment variables from .env file

# --- Configuration ---
# Your Tenable API keys should be stored as environment variables:
# TENABLE_ACCESS_KEY
# TENABLE_SECRET_KEY
# You can also hardcode them here, but it's not recommended for security.
ACCESS_KEY = os.getenv('TENABLE_ACCESS_KEY')
SECRET_KEY = os.getenv('TENABLE_SECRET_KEY')

def export_assets(tio):
    """
    Exports all assets from Tenable.io to a CSV file.
    """
    print("Exporting assets... (this may take a while for large environments)")
    try:
        # Using the iterator to handle pagination automatically
        assets = tio.assets.list()
        
        # We need to get the full list to find all possible headers
        asset_list = list(assets)
        
        if not asset_list:
            print("No assets found.")
            return

        # Dynamically create headers from all keys found in all assets
        headers = sorted(list(set(key for asset in asset_list for key in asset.keys())))

        with open('assets.csv', 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=headers)
            writer.writeheader()
            for asset in asset_list:
                writer.writerow(asset)
        
        print(f"Successfully exported {len(asset_list)} assets to assets.csv")

    except Exception as e:
        print(f"An error occurred during asset export: {e}")

def export_vulnerabilities(tio):
    """
    Exports all vulnerabilities from Tenable.io to a CSV file.
    """
    print("Initiating vulnerability export...")
    try:
        # Start the vulnerability export
        vuln_export = tio.exports.vulns()

        # Wait for the export to finish
        while vuln_export['status'] != 'FINISHED':
            print(f"Vulnerability export status: {vuln_export['status']}...")
            time.sleep(10)
            vuln_export = tio.exports.status('vulns', vuln_export['export_uuid'])

        print("Vulnerability export finished. Downloading results...")

        # Download the chunks
        chunks = tio.exports.download_chunks('vulns', vuln_export['export_uuid'])
        
        headers = None
        total_vulns = 0
        with open('vulnerabilities.csv', 'w', newline='') as csvfile:
            writer = None
            for chunk in chunks:
                if not headers:
                    # The first item in the first chunk determines the headers
                    if chunk:
                        headers = sorted(chunk[0].keys())
                        writer = csv.DictWriter(csvfile, fieldnames=headers)
                        writer.writeheader()
                
                if writer:
                    writer.writerows(chunk)
                    total_vulns += len(chunk)
        
        print(f"Successfully exported {total_vulns} vulnerabilities to vulnerabilities.csv")

    except Exception as e:
        print(f"An error occurred during vulnerability export: {e}")


if __name__ == "__main__":
    if not ACCESS_KEY or not SECRET_KEY:
        print("Error: TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY environment variables must be set.")
        print("Please create a .env file in the same directory with TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY.")
    else:
        print("Connecting to Tenable.io...")
        tio = TenableIO(ACCESS_KEY, SECRET_KEY)
        
        export_assets(tio)
        print("-" * 20)
        export_vulnerabilities(tio)
