import base64
import binascii
import hashlib
import json
import logging
import os
import shlex
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


ACME_FILE = Path(os.environ.get("ACME_FILE", "/letsencrypt/acme.json"))
ACME_RESOLVER = os.environ.get("ACME_RESOLVER", "transip")
TARGET_DOMAIN = os.environ.get("TARGET_DOMAIN", "dns.damandan.nl")
ROUTER_HOST = os.environ.get("ROUTER_HOST", "192.168.2.1")
ROUTER_KEY = "/run/secrets/router_key"
KNOWN_HOSTS = "/run/secrets/known_hosts"
SYNC_INTERVAL_SECONDS = int(os.environ.get("SYNC_INTERVAL_SECONDS", "300"))

CERT_PATH = "/etc/nginx/nginx.cer"
KEY_PATH = "/etc/nginx/nginx.key"
CERT_STAGE = "/etc/nginx/.traefik-cert-sync.cer"
KEY_STAGE = "/etc/nginx/.traefik-cert-sync.key"
MARKER_PATH = "/etc/nginx/.traefik-cert-sync.sha256"

SSH_OPTIONS = [
    "-i",
    ROUTER_KEY,
    "-o",
    "IdentitiesOnly=yes",
    "-o",
    "BatchMode=yes",
    "-o",
    "ConnectTimeout=10",
    "-o",
    "StrictHostKeyChecking=yes",
    "-o",
    "HostKeyAlgorithms=ssh-ed25519",
    "-o",
    f"UserKnownHostsFile={KNOWN_HOSTS}",
]


def run_openssl(arguments, input_data):
    result = subprocess.run(
        ["openssl", *arguments],
        input=input_data,
        capture_output=True,
        check=True,
        timeout=15,
    )
    return result.stdout


def certificate_dates(certificate):
    output = run_openssl(["x509", "-noout", "-dates"], certificate).decode()
    dates = {}
    for line in output.splitlines():
        name, value = line.split("=", 1)
        dates[name] = datetime.strptime(
            value, "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=timezone.utc)
    return dates["notBefore"], dates["notAfter"]


def get_certificate_material():
    store = json.loads(ACME_FILE.read_text())
    resolver = store.get(ACME_RESOLVER)
    if resolver is None:
        raise RuntimeError(f"ACME resolver {ACME_RESOLVER!r} is missing")

    now = datetime.now(timezone.utc)
    candidates = []
    for entry in resolver.get("Certificates", []):
        try:
            certificate = base64.b64decode(entry["certificate"], validate=True)
            private_key = base64.b64decode(entry["key"], validate=True)
        except (KeyError, binascii.Error, ValueError) as error:
            raise RuntimeError("ACME certificate entry is incomplete or invalid") from error

        hostname_check = subprocess.run(
            ["openssl", "x509", "-noout", "-checkhost", TARGET_DOMAIN],
            input=certificate,
            capture_output=True,
            check=False,
            timeout=15,
        )
        if hostname_check.returncode != 0:
            continue

        not_before, not_after = certificate_dates(certificate)
        if not_before <= now < not_after:
            candidates.append((not_after, certificate, private_key))

    if not candidates:
        raise RuntimeError(f"No valid ACME certificate covers {TARGET_DOMAIN}")

    _, certificate, private_key = max(candidates, key=lambda item: item[0])
    certificate_public_key = run_openssl(
        ["x509", "-pubkey", "-noout"], certificate
    )
    private_public_key = run_openssl(["pkey", "-pubout"], private_key)
    if hashlib.sha256(certificate_public_key).digest() != hashlib.sha256(
        private_public_key
    ).digest():
        raise RuntimeError("The ACME certificate and private key do not match")

    return certificate, private_key


def run_ssh(remote_command, input_data=None):
    result = subprocess.run(
        [
            "ssh",
            *SSH_OPTIONS,
            f"root@{ROUTER_HOST}",
            remote_command,
        ],
        input=input_data,
        capture_output=True,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.decode(errors="replace").strip()
        raise RuntimeError(f"Router SSH command failed: {detail}")
    return result.stdout.decode(errors="replace")


def remote_state():
    command = f"""set -eu
for path in {shlex.quote(CERT_PATH)} {shlex.quote(KEY_PATH)}; do
    if [ -f "$path" ]; then
        printf 'file '
        sha256sum "$path"
    else
        printf 'missing %s\\n' "$path"
    fi
done
if [ -f {shlex.quote(MARKER_PATH)} ]; then
    printf 'marker '
    cat {shlex.quote(MARKER_PATH)}
else
    printf 'missing-marker\\n'
fi"""
    state = {}
    for line in run_ssh(command).splitlines():
        if line.startswith("file "):
            digest, path = line[5:].split(maxsplit=1)
            state[path] = digest
        elif line.startswith("missing "):
            state[line[8:]] = None
        elif line.startswith("marker "):
            state["marker"] = line[7:].strip()
    return state


def upload(path, contents):
    run_ssh(f"umask 077; cat > {shlex.quote(path)}", contents)


def install_remote_certificate(certificate, private_key, generation):
    certificate_hash = hashlib.sha256(certificate).hexdigest()
    key_hash = hashlib.sha256(private_key).hexdigest()
    cert_new = f"{CERT_PATH}.traefik-new"
    key_new = f"{KEY_PATH}.traefik-new"
    cert_backup = f"{CERT_PATH}.traefik-backup"
    key_backup = f"{KEY_PATH}.traefik-backup"

    command = f"""set -eu
cert_stage={shlex.quote(CERT_STAGE)}
key_stage={shlex.quote(KEY_STAGE)}
trap 'rm -f "$cert_stage" "$key_stage" {shlex.quote(cert_new)} {shlex.quote(key_new)}' EXIT
[ "$(sha256sum "$cert_stage" | cut -d ' ' -f 1)" = {shlex.quote(certificate_hash)} ]
[ "$(sha256sum "$key_stage" | cut -d ' ' -f 1)" = {shlex.quote(key_hash)} ]
openssl x509 -in "$cert_stage" -noout -checkhost {shlex.quote(TARGET_DOMAIN)}
openssl pkey -in "$key_stage" -check -noout
cert_public=$(openssl x509 -in "$cert_stage" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum | cut -d ' ' -f 1)
key_public=$(openssl pkey -in "$key_stage" -pubout -outform DER | sha256sum | cut -d ' ' -f 1)
[ "$cert_public" = "$key_public" ]
cp "$cert_stage" {shlex.quote(cert_new)}
chmod 0644 {shlex.quote(cert_new)}
cp "$key_stage" {shlex.quote(key_new)}
chmod 0600 {shlex.quote(key_new)}
cp -p {shlex.quote(CERT_PATH)} {shlex.quote(cert_backup)}
cp -p {shlex.quote(KEY_PATH)} {shlex.quote(key_backup)}
mv {shlex.quote(cert_new)} {shlex.quote(CERT_PATH)}
mv {shlex.quote(key_new)} {shlex.quote(KEY_PATH)}
if ! nginx -t; then
    mv {shlex.quote(cert_backup)} {shlex.quote(CERT_PATH)}
    mv {shlex.quote(key_backup)} {shlex.quote(KEY_PATH)}
    nginx -t
    /etc/init.d/nginx reload
    exit 1
fi
if ! /etc/init.d/nginx reload; then
    mv {shlex.quote(cert_backup)} {shlex.quote(CERT_PATH)}
    mv {shlex.quote(key_backup)} {shlex.quote(KEY_PATH)}
    /etc/init.d/nginx reload
    exit 1
fi
if ! /etc/init.d/adguardhome restart; then
    mv {shlex.quote(cert_backup)} {shlex.quote(CERT_PATH)}
    mv {shlex.quote(key_backup)} {shlex.quote(KEY_PATH)}
    /etc/init.d/nginx reload
    /etc/init.d/adguardhome restart
    exit 1
fi
printf '%s\\n' {shlex.quote(generation)} > {shlex.quote(MARKER_PATH)}.tmp
chmod 0600 {shlex.quote(MARKER_PATH)}.tmp
mv {shlex.quote(MARKER_PATH)}.tmp {shlex.quote(MARKER_PATH)}"""

    upload(CERT_STAGE, certificate)
    upload(KEY_STAGE, private_key)
    run_ssh(command)


def sync_once():
    certificate, private_key = get_certificate_material()
    certificate_hash = hashlib.sha256(certificate).hexdigest()
    key_hash = hashlib.sha256(private_key).hexdigest()
    generation = hashlib.sha256(certificate + b"\0" + private_key).hexdigest()
    state = remote_state()

    if (
        state.get(CERT_PATH) == certificate_hash
        and state.get(KEY_PATH) == key_hash
        and state.get("marker") == generation
    ):
        logging.info("Router certificate and key are already current")
        return

    logging.info("Router certificate differs from Traefik; deploying the current certificate")
    install_remote_certificate(certificate, private_key, generation)
    logging.info("Certificate deployed; Nginx and AdGuard Home were reloaded")


def main():
    if SYNC_INTERVAL_SECONDS < 30:
        raise ValueError("SYNC_INTERVAL_SECONDS must be at least 30")
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    while True:
        try:
            sync_once()
        except json.JSONDecodeError as error:
            logging.warning(
                "ACME storage was not valid JSON; it will be retried: %s", error
            )
        time.sleep(SYNC_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
