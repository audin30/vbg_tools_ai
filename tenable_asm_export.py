import os
import csv
import argparse
from tenable.asm import TenableASM
from dotenv import load_dotenv

load_dotenv()

# --- Configuration ---
# Your Tenable ASM API key should be stored as an environment variable:
# TENABLE_ASM_API_KEY
# You can also hardcode it here, but it's not recommended for security.
API_KEY = os.getenv('TENABLE_ASM_API_KEY')
URL = os.getenv('TASM_URL', 'https://asm.cloud.tenable.com')

# A comprehensive list of known columns.
KNOWN_COLUMNS = [
    "id", "severity", "added_to_inventory", "tag", "ip", "port", "protocol",
    "service", "product", "version", "os", "hostname", "domain", "subdomain",
    "first_seen", "last_seen", "last_modified", "status", "type", "source",
    "description", "notes", "business_criticality", "owner", "location", "tags",
    "vulnerabilities", "cves", "exploits", "malware", "open_ports",
    "web_technologies", "whois.administrative_contact_email",
    "whois.administrative_contact_name", "whois.administrative_contact_organization",
    "whois.administrative_contact_street", "whois.administrative_contact_city",
    "whois.administrative_contact_state", "whois.administrative_contact_zip",
    "whois.administrative_contact_country", "whois.creation_date",
    "whois.expiration_date", "whois.name_server", "whois.registrant_contact_email",
    "whois.registrant_contact_name", "whois.registrant_contact_organization",
    "whois.registrant_contact_street", "whois.registrant_contact_city",
    "whois.registrant_contact_state", "whois.registrant_contact_zip",
    "whois.registrant_contact_country", "whois.registrar_name",
    "whois.updated_date", "whois.technical_contact_email",
    "whois.technical_contact_name", "whois.technical_contact_organization",
    "whois.technical_contact_street", "whois.technical_contact_city",
    "whois.technical_contact_state", "whois.technical_contact_zip",
    "whois.technical_contact_country", "dns.a_record", "dns.aaaa_record",
    "dns.cname_record", "dns.mx_record", "dns.ns_record", "dns.soa_record",
    "dns.txt_record", "dns.spf_record", "dns.dmarc_record", "dns.ptr_record",
    "dns.srv_record", "dns.caa_record", "dns.dnssec_record",
    "ssl.common_name", "ssl.organization", "ssl.issuer", "ssl.expiration_date",
    "ssl.valid_from", "ssl.serial_number", "ssl.fingerprint_sha1",
    "ssl.fingerprint_sha256", "ssl.subject_alternative_names",
    "ssl.protocols", "ssl.ciphers", "ssl.errors", "ssl.ev_certificate",
    "ssl.country", "ssl.state", "ssl.city", "ssl.postal_code",
    "ssl.street_address", "ssl.unit", "ssl.email_address", "ssl.phone_number",
    "ssl.fax_number", "ssl.uri", "ssl.dns_names", "ssl.ip_addresses",
    "ssl.public_key_algorithm", "ssl.public_key_size",
    "ssl.signature_algorithm", "ssl.version", "ssl.extensions",
    "ssl.trust_chain", "ssl.self_signed", "ssl.revoked", "ssl.expired",
    "ssl.not_yet_valid", "ssl.weak_signature", "ssl.weak_key",
    "ssl.heartbleed_vulnerable", "ssl.poodle_vulnerable",
    "ssl.freak_vulnerable", "ssl.logjam_vulnerable", "ssl.drown_vulnerable",
    "ssl.sweet32_vulnerable", "ssl.robot_vulnerable", "ssl.crime_vulnerable",
    "ssl.breach_vulnerable", "ssl.beast_vulnerable", "ssl.rc4_vulnerable",
    "ssl.3des_vulnerable", "ssl.md5_vulnerable", "ssl.sha1_vulnerable",
    "ssl.sha256_vulnerable", "ssl.sha512_vulnerable", "ssl.ecc_vulnerable",
    "ssl.rsa_vulnerable", "ssl.dsa_vulnerable", "ssl.dh_vulnerable",
    "ssl.export_cipher_suite", "ssl.forward_secrecy", "ssl.hsts",
    "ssl.ocsp_stapling", "ssl.sct", "ssl.caa_record_present",
    "ssl.caa_record_valid", "ssl.dns_caa_record_present",
    "ssl.dns_caa_record_valid", "ssl.dnssec_valid", "ssl.dnssec_signed",
    "ssl.dnssec_untrusted", "ssl.dnssec_bogus", "ssl.dnssec_nsec",
    "ssl.dnssec_nsec3", "ssl.dnssec_rrsig", "ssl.dnssec_ds",
    "ssl.dnssec_dnskey", "ssl.dnssec_nsec3param", "ssl.dnssec_cdnskey",
    "ssl.dnssec_cds", "ssl.dnssec_dlv", "ssl.dnssec_ta",
    "ssl.dnssec_trust_anchor", "ssl.dnssec_validated",
    "ssl.dnssec_validation_error", "ssl.dnssec_validation_warning",
    "ssl.dnssec_validation_info", "ssl.dnssec_validation_debug",
    "ssl.dnssec_validation_trace", "ssl.dnssec_validation_unknown",
    "ssl.dnssec_validation_none", "ssl.dnssec_validation_other",
    "ssl.dnssec_validation_status", "ssl.dnssec_validation_status_code",
    "app_updates"
]

def flatten_dict(d, parent_key='', sep='.'):
    items = []
    for k, v in d.items():
        new_key = parent_key + sep + k if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)

def export_asm_assets(api_key, url, output_file):
    """
    Exports all assets from Tenable ASM to a CSV file.
    """
    print("Connecting to Tenable ASM...")
    try:
        asm = TenableASM(api_key=api_key, url=url)
        print("Exporting assets... (this may take a while for large environments)")
        
        assets = asm.inventory.list()
        asset_list = [flatten_dict(asset) for asset in assets]
        
        if not asset_list:
            print("No assets found.")
            return

        # Dynamically discover new columns
        all_keys = set(KNOWN_COLUMNS)
        new_keys = set()
        for asset in asset_list:
            for key in asset.keys():
                if key not in all_keys:
                    new_keys.add(key)
        
        if new_keys:
            print(f"Warning: Found new columns not in the known list: {new_keys}")
            all_keys.update(new_keys)

        headers = sorted(list(all_keys))
            
        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=headers)
            writer.writeheader()
            writer.writerows(asset_list)
            
        print(f"Successfully exported {len(asset_list)} assets to {output_file}")
        
    except Exception as e:
        print(f"An error occurred during asset export: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Export assets from Tenable ASM.")
    parser.add_argument('-o', '--output', default='tenable_asm_assets.csv', help='Output file name (default: tenable_asm_assets.csv)')
    parser.add_argument('--url', default=URL, help=f'Tenable ASM URL (default: {URL})')
    args = parser.parse_args()

    if not API_KEY:
        print("Error: TENABLE_ASM_API_KEY environment variable must be set.")
        print("Please create a .env file in the same directory with TENABLE_ASM_API_KEY.")
    else:
        export_asm_assets(API_KEY, args.url, args.output)
