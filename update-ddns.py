#!/usr/bin/python3

import os
import logging
import argparse
from datetime import datetime

import requests

IP_URL = "https://checkip.amazonaws.com/"
DO_API_URL = "https://api.digitalocean.com/v2"

logging.basicConfig(level=logging.INFO)


# User-defined exceptions.
class NoIPException(Exception):
    pass


class NoRecordsException(Exception):
    pass


class NoDomainException(Exception):
    pass


class RecordUpdateException(Exception):
    pass


def update_dns(record_id, record, domain, ip, ttl, token, webhook_url=""):
    """Updates the DNS record using the DigitalOcean API."""
    url = f"{DO_API_URL}/domains/{domain}/records/{record_id}"

    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    data = {"type": "A", "data": str(ip), "ttl": str(ttl)}

    r = requests.put(url, headers=headers, json=data)

    if r.status_code == 200:
        message = f"Record {record}.{domain} updated to {ip} with a TTL of {ttl}."

        logging.info(message)

        if webhook_url:
            md_message = f"Record **{record}.{domain}** updated to `{ip}` with a TTL of {ttl}."
 
            send_webhook(webhook_url, md_message)

    else:
        raise RecordUpdateException(f"Error updating DNS record: {r.text}")


def get_current_dns(record, domain, token):
    """Return the current IPv4 for the DNS record."""
    url = f"{DO_API_URL}/domains/{domain}/records"

    headers = {
        "Authorization": f"Bearer {token}",
    }

    r = requests.get(url, headers=headers)

    if r.status_code != 200:
        raise NoRecordsException(r.text)

    data = r.json()

    for do_record in data["domain_records"]:
        if do_record["type"] == "A" and do_record["name"] == record:
            return (do_record["data"], do_record["id"])

    return (None, None)


def get_ip():
    """Return the current public IPv4."""
    r = requests.get(IP_URL)

    if r.status_code != 200:
        raise NoIPException(f"Error getting DNS records: {r.text}")

    ip = r.text.strip()
    logging.info(f"Real IP is {ip}")

    return ip


def send_webhook(webhook_url, description, colour=0x0080ff):
    data = {
        "content": ""
    }

    role_id = "<@&1013627796112805928>"

    data["embeds"] = [
        {
            "title": "DDNS Alert",
            "description": description + f"\n\n{role_id}",
            "color": colour,
            "timestamp": datetime.utcnow().isoformat(),
            "footer": {
                "text": "DDNS"
            }
        }
    ]

    requests.post(webhook_url, json=data)

    logging.info("Webhook sent.")


def parse_args():
    """Parse arguments from the CLI."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-t", "--token", type=str, default=os.environ.get("DIGITALOCEAN_TOKEN")
    )
    parser.add_argument(
        "-w", "--webhook-url", type=str, default=os.environ.get("WEBHOOK_URL")
    )
    parser.add_argument("--ttl", type=str, default="60")
    parser.add_argument("record", type=str)
    parser.add_argument("domain", type=str)

    return parser.parse_args()


def main():
    """Main."""

    try:
        args = parse_args()

        real_ip = get_ip()
        current_ip, record_id = get_current_dns(args.record, args.domain, args.token)

        if record_id is None or current_ip is None:
            raise NoDomainException(f"Record {args.record}.{args.domain} does not exist. Please create an initial A record before running this script.")

        if real_ip != current_ip:
            update_dns(record_id, args.record, args.domain, real_ip, args.ttl, args.token, webhook_url=args.webhook_url)
        else:
            logging.info("Current DNS matches real IP. Skipping update.")

    except Exception as e:
        logging.error(e)

        if args.webhook_url:
            send_webhook(
                args.webhook_url,
                f"Exception: {e}",
                colour=0xff0000
            )

        exit(1)


if __name__ == "__main__":
    main()
