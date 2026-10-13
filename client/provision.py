"""Trusted control-plane utility for issuing a scoped demo token to a file."""
import argparse
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from evaluate import Client, provision


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8080")
    parser.add_argument("--admin-file", default="secrets/admin.token")
    parser.add_argument("--output", default=".local/agent.token")
    args = parser.parse_args()
    admin = Client(args.url, pathlib.Path(args.admin_file).read_text().strip())
    grant = provision(admin)
    path = pathlib.Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as file:
        file.write(grant["access_token"] + "\n")
    print("Scoped five-minute token written to", path)
    print("Grant ID:", grant["grant"]["id"])


if __name__ == "__main__":
    main()
