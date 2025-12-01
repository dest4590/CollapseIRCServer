import os
import socket
import sys
import time
from typing import Optional
from dotenv import load_dotenv

load_dotenv()


def connect_and_auth(
    host: str, port: int, user_id: str, username: str, token: str, client_name: str
) -> Optional[socket.socket]:
    try:
        sock = socket.create_connection((host, port), timeout=10)
    except Exception as e:
        print(f"[connect] Failed to connect to {host}:{port}: {e}")
        return None

    auth_line = f"{user_id}@:@{username}@:@{token}@:@{client_name}"

    try:
        sock.sendall((auth_line + "\n").encode("utf-8"))
    except Exception as e:
        print(f"[auth] Failed to send auth line: {e}")
        try:
            sock.close()
        except Exception:
            pass
        return None

    return sock


def tail_socket(sock: socket.socket) -> None:
    f = sock.makefile("r", encoding="utf-8", errors="replace")
    try:
        for raw in f:
            line = raw.rstrip("\r\n")
            ts = time.strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{ts}] {line}")
    except Exception as e:
        print(f"[read] error: {e}")
    finally:
        try:
            f.close()
        except Exception:
            pass


def main() -> None:
    host = os.getenv("IRC_HOST", "127.0.0.1")
    port = int(os.getenv("IRC_PORT", "1338"))
    user_id = os.getenv("IRC_USER_ID")
    username = os.getenv("IRC_USERNAME")
    token = os.getenv("IRC_TOKEN")
    client_name = os.getenv("IRC_CLIENT", "irc_wather")

    if not user_id or not username or not token:
        print(
            "Missing required credentials in .env: IRC_USER_ID, IRC_USERNAME, IRC_TOKEN"
        )
        sys.exit(2)

    print(
        f"Connecting to {host}:{port} as {username} (id={user_id}) using client={client_name}"
    )

    backoff = 1.0
    try:
        while True:
            sock = connect_and_auth(host, port, user_id, username, token, client_name)
            if not sock:
                print(f"Reconnect in {backoff:.1f}s...")
                time.sleep(backoff)
                backoff = min(backoff * 2, 30.0)
                continue

            backoff = 1.0
            print("Connected — listening for messages. Ctrl-C to stop.")
            try:
                tail_socket(sock)
            finally:
                try:
                    sock.close()
                except Exception:
                    pass

            print("Disconnected. Reconnecting...")
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\nExiting.")


if __name__ == "__main__":
    main()
