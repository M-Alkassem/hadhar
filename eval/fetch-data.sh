#!/usr/bin/env bash
# Downloads the public evaluation data into eval/cache (not committed: licences differ and the feeds change daily).
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p cache && cd cache
echo "UCI SMS Spam Collection..."
curl -sL --retry 3 -o sms.zip "https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip" && unzip -o -q sms.zip
echo "OpenPhish community feed (live phishing URLs)..."
curl -sL --retry 3 -o openphish.txt "https://openphish.com/feed.txt"
echo "Tranco top-1M (benign domains, ~10 MB)..."
curl -sL --retry 3 -m 600 -o tranco.zip "https://tranco-list.eu/download/daily/top-1m.csv.zip" && unzip -o -q tranco.zip
echo "done: $(wc -l < SMSSpamCollection) sms, $(wc -l < openphish.txt) phishing urls, $(wc -l < top-1m.csv) domains"
