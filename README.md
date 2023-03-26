# DigitalOcean DDNS Updater
This simple script is used to update a DNS record with the current public IP using the DigitalOcean API. Run this every now and then in a cron job to simulate dynamic DNS.

## Usage
```
usage: update-ddns.py [-h] [-t TOKEN] [--ttl TTL] record domain

positional arguments:
  record
  domain

options:
  -h, --help            show this help message and exit
  -t TOKEN, --token TOKEN
  -w WEBHOOK_URL, --webhook-url WEBHOOK_URL
  --ttl TTL
```

You can also set your DigitalOcean token using `export DIGITALOCEAN_TOKEN=<token>`.
