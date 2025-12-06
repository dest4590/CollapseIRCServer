import argparse
import os
import socket
import sys
import time
from typing import Optional
from dotenv import load_dotenv


load_dotenv()


def send_line(sock: socket.socket, line: str) -> None:
    sock.sendall((line + "\n").encode("utf-8"))


def connect_and_auth(
    host: str, port: int, token: str, client_name: str
) -> Optional[socket.socket]:
    try:
        sock = socket.create_connection((host, port), timeout=5)
    except Exception as e:
        print(f"Failed to connect to {host}:{port}: {e}")
        return None

    auth_line = f"@:@{token}@:@{client_name}"
    try:
        send_line(sock, auth_line)
    except Exception as e:
        print(f"Failed to send auth line: {e}")
        try:
            sock.close()
        except Exception:
            pass
        return None

    return sock


def main():
    parser = argparse.ArgumentParser(
        description="Simple IRC CLI (sends one or more messages)"
    )
    parser.add_argument(
        "--message",
        "-m",
        help="Message to send. If omitted, read from stdin until EOF.",
    )
    parser.add_argument("--host", help="Override host from .env")
    parser.add_argument("--port", type=int, help="Override port from .env")
    parser.add_argument(
        "--wait",
        type=float,
        default=0.5,
        help="Seconds to wait for server response before exiting",
    )

    args = parser.parse_args()

    host = args.host or os.getenv("IRC_HOST", "127.0.0.1")
    port = args.port or int(os.getenv("IRC_PORT", "1338"))
    token = os.getenv("IRC_TOKEN")
    client_name = os.getenv("IRC_CLIENT", "irc_tester")

    if not token:
        print("Missing required credentials in .env: IRC_TOKEN")
        sys.exit(2)

    if args.message:
        messages = [args.message]
    else:
        try:
            msg = input("Enter message: ")
        except EOFError:
            print("No message provided")
            sys.exit(1)
        if not msg:
            print("No message provided")
            sys.exit(1)
        messages = [msg]

    sock = connect_and_auth(host, port, token, client_name)
    if not sock:
        sys.exit(1)

    try:
        for msg in messages:
            try:
                send_line(sock, msg)
                print(f"Sent: {msg}")
            except Exception as e:
                print(f"Failed to send message: {e}")
        time.sleep(args.wait)
    finally:
        try:
            sock.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
