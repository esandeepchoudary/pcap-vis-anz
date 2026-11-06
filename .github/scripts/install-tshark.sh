#!/usr/bin/env bash
# Install tshark on a CI runner. The Ubuntu mirror sometimes stalls mid-download, so each attempt is
# time-boxed and apt itself times out and retries slow connections.
set -u
echo "wireshark-common wireshark-common/install-setuid boolean false" | sudo debconf-set-selections
APT_OPTS=(-o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 -o Acquire::Retries=5)
for attempt in 1 2 3; do
  if timeout 240 sudo apt-get "${APT_OPTS[@]}" update -q \
     && timeout 240 sudo DEBIAN_FRONTEND=noninteractive apt-get "${APT_OPTS[@]}" install -y -q --no-install-recommends tshark; then
    tshark --version | head -1
    exit 0
  fi
  echo "tshark install attempt $attempt failed; retrying" >&2
  sleep 10
done
exit 1
