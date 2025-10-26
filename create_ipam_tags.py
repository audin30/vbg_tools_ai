import csv
import json
import time
import ipaddress
import requests
import argparse
from datetime import datetime

# === CONFIG ===
CSV_FILE = "subnets.csv"
LOG_CSV = "tagging_log.csv"
LOG_JSON = "tagging_log.json"
TENABLE_URL = "https://cloud.tenable.com"
TENABLE_HEADERS = {
    "X-ApiKeys": "accessKey=YOUR_ACCESS_KEY; secretKey=YOUR_SECRET_KEY",
    "Content-Type": "application/json"
}

# Rate limiting (seconds between API calls)
API_DELAY = 0.5

# Slack webhook (paste your Slack Incoming Webhook URL)
SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/XXXX/YYYY/ZZZZ"  # <-- replace


# === STEP 1: Load subnets from CSV ===
def load_subnets(csv_file):
    subnets = []
    with open(csv_file, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            subnets.append({
                "cidr": row["CIDR"].strip(),
                "owner": row.get("Owner", "").strip(),
                "description": row.get("Description", "").strip()
            })
    return subnets


# === STEP 2: Get existing tag definitions ===
def get_existing_tags(dry_run=False):
    if dry_run:
        print("💡 Dry-run: skipping tag retrieval.")
        return {}
    all_tags = {}
    url = f"{TENABLE_URL}/tags/definitions"
    while url:
        resp = requests.get(url, headers=TENABLE_HEADERS)
        resp.raise_for_status()
        data = resp.json()
        for tag in data.get("tags", []):
            key = f"{tag['category_name']}:{tag['value']}"
            all_tags[key] = tag["uuid"]
        url = data.get("pagination", {}).get("next")
        time.sleep(API_DELAY)
    return all_tags


# === STEP 3: Create new tag definition if missing ===
def create_tag_definition(category, value, dry_run=False):
    if dry_run:
        print(f"💡 Dry-run: would create tag {category}:{value}")
        return f"fake-uuid-{category}-{value}"
    payload = {
        "category_name": category,
        "value": value,
        "category_description": f"Auto-created for {category}"
    }
    resp = requests.post(f"{TENABLE_URL}/tags/definitions", headers=TENABLE_HEADERS, json=payload)
    time.sleep(API_DELAY)
    if resp.status_code not in (200, 201):
        print(f"⚠️ Failed to create tag {category}:{value} - {resp.status_code} {resp.text}")
        return None
    tag_uuid = resp.json()["uuid"]
    print(f"🆕 Created tag: {category}:{value}")
    return tag_uuid


# === STEP 4: Get assets ===
def get_tenable_assets(dry_run=False):
    if dry_run:
        print("💡 Dry-run: skipping asset retrieval.")
        return [
            {"id": "dryrun-asset-1", "ipv4s": ["10.0.0.15"]},
            {"id": "dryrun-asset-2", "ipv4s": ["192.168.1.22"]}
        ]
    assets = []
    url = f"{TENABLE_URL}/assets"
    while url:
        resp = requests.get(url, headers=TENABLE_HEADERS)
        resp.raise_for_status()
        data = resp.json()
        assets.extend(data.get("assets", []))
        url = data.get("pagination", {}).get("next")
        time.sleep(API_DELAY)
    return assets


# === STEP 5: Logging helpers ===
def init_logs():
    with open(LOG_CSV, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "asset_id", "ip", "tags", "status", "message"])
    with open(LOG_JSON, "w") as f:
        json.dump([], f)


def write_log(entry):
    timestamp = datetime.utcnow().isoformat()
    csv_entry = [
        timestamp,
        entry.get("asset_id"),
        entry.get("ip"),
        ", ".join(entry.get("tags", [])),
        entry.get("status"),
        entry.get("message", "")
    ]
    with open(LOG_CSV, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(csv_entry)
    with open(LOG_JSON, "r+") as f:
        data = json.load(f)
        data.append({**entry, "timestamp": timestamp})
        f.seek(0)
        json.dump(data, f, indent=2)


# === STEP 6: Assign tags ===
def assign_tags(assets, subnets, existing_tags, dry_run=False):
    summary = {"success": 0, "error": 0, "dryrun": 0}
    for asset in assets:
        asset_id = asset.get("id")
        ipv4s = asset.get("ipv4s", [])
        if not ipv4s:
            continue

        for ip in ipv4s:
            for subnet in subnets:
                try:
                    if ipaddress.ip_address(ip) in ipaddress.ip_network(subnet["cidr"], strict=False):
                        tags_to_apply = {}
                        for category, value in [
                            ("Owner", subnet["owner"]),
                            ("CIDR", subnet["cidr"]),
                            ("Description", subnet["description"])
                        ]:
                            key = f"{category}:{value}"
                            if key not in existing_tags:
                                tag_uuid = create_tag_definition(category, value, dry_run)
                                if tag_uuid:
                                    existing_tags[key] = tag_uuid
                            tags_to_apply[key] = existing_tags.get(key)

                        if dry_run:
                            msg = f"💡 Dry-run: would tag {asset_id} ({ip}) with {list(tags_to_apply.keys())}"
                            print(msg)
                            write_log({
                                "asset_id": asset_id,
                                "ip": ip,
                                "tags": list(tags_to_apply.keys()),
                                "status": "dry-run",
                                "message": msg
                            })
                            summary["dryrun"] += 1
                        else:
                            tag_payload = {"assets": [asset_id], "tags": list(tags_to_apply.values())}
                            resp = requests.patch(
                                f"{TENABLE_URL}/tags/assets/assignments",
                                headers=TENABLE_HEADERS,
                                json=tag_payload
                            )
                            time.sleep(API_DELAY)

                            if resp.status_code in (200, 204):
                                msg = f"Tagged {asset_id} ({ip}) with {list(tags_to_apply.keys())}"
                                print(f"✅ {msg}")
                                write_log({
                                    "asset_id": asset_id,
                                    "ip": ip,
                                    "tags": list(tags_to_apply.keys()),
                                    "status": "success",
                                    "message": msg
                                })
                                summary["success"] += 1
                            else:
                                msg = f"Failed to tag asset: {resp.status_code} - {resp.text}"
                                print(f"⚠️ {msg}")
                                write_log({
                                    "asset_id": asset_id,
                                    "ip": ip,
                                    "tags": list(tags_to_apply.keys()),
                                    "status": "error",
                                    "message": msg
                                })
                                summary["error"] += 1
                        break
                except ValueError:
                    continue
    return summary


# === STEP 7: Slack Notification ===
def send_slack_summary(summary, dry_run=False):
    if not SLACK_WEBHOOK_URL or "hooks.slack.com" not in SLACK_WEBHOOK_URL:
        print("⚠️ Slack webhook not configured. Skipping Slack notification.")
        return

    emoji = "🧪" if dry_run else ("✅" if summary["error"] == 0 else "⚠️")
    mode = "DRY-RUN" if dry_run else "LIVE"

    message = (
        f"{emoji} *Tenable Tag Sync Summary ({mode})*\n"
        f"• Success: {summary['success']}\n"
        f"• Errors: {summary['error']}\n"
        f"• Dry-run actions: {summary['dryrun']}\n"
        f"• Logs: `{LOG_CSV}`, `{LOG_JSON}`"
    )

    payload = {"text": message}
    try:
        resp = requests.post(SLACK_WEBHOOK_URL, json=payload)
        if resp.status_code == 200:
            print("📨 Slack notification sent.")
        else:
            print(f"⚠️ Slack webhook failed: {resp.status_code} {resp.text}")
    except Exception as e:
        print(f"⚠️ Slack notification error: {e}")


# === MAIN ===
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sync Tenable tags from CSV")
    parser.add_argument("--dry-run", action="store_true", help="Run without making any API changes")
    args = parser.parse_args()
    dry_run = args.dry_run

    print("🚀 Starting Tenable tag updater...")
    if dry_run:
        print("⚙️  DRY-RUN MODE ENABLED — no changes will be made.")

    subnets = load_subnets(CSV_FILE)
    print(f"📥 Loaded {len(subnets)} subnets")

    init_logs()

    existing_tags = get_existing_tags(dry_run)
    print(f"🔖 Loaded {len(existing_tags)} existing tag definitions")

    assets = get_tenable_assets(dry_run)
    print(f"🖥️ Loaded {len(assets)} assets")

    summary = assign_tags(assets, subnets, existing_tags, dry_run)

    print(f"✅ Completed. Logs saved to {LOG_CSV} and {LOG_JSON}")
    send_slack_summary(summary, dry_run)