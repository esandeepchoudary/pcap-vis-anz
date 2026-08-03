---
sidebar_position: 2
sidebar_label: "Getting started"
title: "Getting started"
description: "Python 3.8+ and pip."
---

# Getting started

## Requirements

Python 3.8+ and pip.

## Install

Clone the repository and enter it:

```bash
git clone https://github.com/esandeepchoudary/pcap-vis-anz.git
cd pcap-vis-anz
```

Optionally create a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate        # Linux / macOS
venv\Scripts\activate           # Windows
```

Install dependencies:

```bash
pip install -r requirements.txt
```

On Kali/Debian systems, if pip complains about an externally managed environment, add `--break-system-packages`:

```bash
pip install -r requirements.txt --break-system-packages
```

## Run

Start the app with:

```bash
python app.py                # localhost only (default, safe)
python app.py --public       # expose to your local network
python app.py --port 8080    # use a different port
```

Then open `http://localhost:5000` in a browser (or your machine's LAN IP if `--public` was used). Upload a capture file (`.pcap`, `.pcapng`, or `.cap`, up to 1 GB) and the graph renders automatically.

The `--public` flag binds the Werkzeug development server to `0.0.0.0`, which is not hardened for production use — anyone on the same network could upload arbitrary files to the process. It should only be used on fully trusted, isolated networks. For long-running or multi-user deployments, the README recommends running behind gunicorn instead:

```bash
pip install gunicorn
gunicorn -w 2 -b 0.0.0.0:5000 'app:app'
```

## Capturing your own traffic

If you don't already have a capture file, one can be created with `tcpdump`:

```bash
# Capture 60 seconds of traffic on any interface
sudo tcpdump -i any -w capture.pcap -G 60 -W 1

# Or capture on a specific interface
sudo tcpdump -i eth0 -w capture.pcap
```

Sample `.pcap` files are also available from malware-traffic-analysis.net and the Wireshark sample captures page, per the README.

<!-- docsolace:keep -->
<!-- Notes added here are preserved across regeneration. -->
<!-- /docsolace:keep -->
