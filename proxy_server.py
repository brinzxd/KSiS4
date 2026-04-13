#!/usr/bin/env python3
"""
HTTP Proxy Server with logging and blacklist filtering.
Lab: HTTP protocol, socket programming, multithreading.
Usage: python3 proxy_server.py
Then configure browser to use HTTP proxy 127.0.0.1:8080
"""

import socket
import threading
import os
import json
from datetime import datetime
from urllib.parse import urlparse

# ─── Config ────────────────────────────────────────────────────────────────────

CONFIG_FILE    = "proxy_config.json"
BLACKLIST_FILE = "blacklist.txt"

DEFAULT_CONFIG = {
    "host": "127.0.0.1",
    "port": 8080,
    "buffer_size": 4096
}

# ─── ANSI colors ───────────────────────────────────────────────────────────────

RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
GRAY   = "\033[90m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

# ─── Config loader ─────────────────────────────────────────────────────────────

def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            print(f"{GREEN}[CONFIG]{RESET} Loaded config from {CONFIG_FILE}")
            return cfg
        except Exception as e:
            print(f"{YELLOW}[CONFIG]{RESET} Failed to load {CONFIG_FILE}: {e}. Using defaults.")
    else:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2, ensure_ascii=False)
        print(f"{CYAN}[CONFIG]{RESET} Created default config: {CONFIG_FILE}")
    return DEFAULT_CONFIG.copy()

# ─── Blacklist loader ──────────────────────────────────────────────────────────

def load_blacklist() -> list[str]:
    """
    Read blacklist from BLACKLIST_FILE (one entry per line).
    Lines starting with # are treated as comments and ignored.
    Empty lines are ignored.
    Returns a list of lowercase domain/URL strings.
    """
    if not os.path.exists(BLACKLIST_FILE):
        # Create a sample blacklist file if it doesn't exist
        sample = (
            "# HTTP Proxy — Blacklist\n"
            "# One entry per line: domain or full URL prefix\n"
            "# Lines starting with # are comments\n"
            "#\n"
            "# Examples:\n"
            "#   example-blocked.com        — blocks domain and all subdomains\n"
            "#   ads.example.com            — blocks only this subdomain\n"
            "#   http://example.com/ads/    — blocks specific URL prefix\n"
            "#\n"
            "example-blocked.com\n"
            "ads.example.com\n"
        )
        with open(BLACKLIST_FILE, "w", encoding="utf-8") as f:
            f.write(sample)
        print(f"{CYAN}[BLACKLIST]{RESET} Created sample blacklist: {BLACKLIST_FILE}")
        return ["example-blocked.com", "ads.example.com"]

    entries = []
    with open(BLACKLIST_FILE, "r", encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            entries.append(line.lower())

    print(f"{GREEN}[BLACKLIST]{RESET} Loaded {len(entries)} entries from {BLACKLIST_FILE}")
    return entries

# ─── Logging ───────────────────────────────────────────────────────────────────

log_lock = threading.Lock()
request_count = 0

def log(method, url, status_code, blocked=False, extra=""):
    global request_count
    with log_lock:
        request_count += 1
        ts = datetime.now().strftime("%H:%M:%S")
        num = f"{GRAY}#{request_count:04d}{RESET}"
        ts_str = f"{GRAY}[{ts}]{RESET}"

        if blocked:
            status_str = f"{RED}BLOCKED {RESET}"
        elif status_code and status_code < 300:
            status_str = f"{GREEN}{status_code:<7} {RESET}"
        elif status_code and status_code < 400:
            status_str = f"{YELLOW}{status_code:<7} {RESET}"
        elif status_code:
            status_str = f"{RED}{status_code:<7} {RESET}"
        else:
            status_str = f"{GRAY}---     {RESET}"

        method_str = f"{CYAN}{method:<8}{RESET}"
        url_display = url if len(url) <= 80 else url[:77] + "..."
        extra_str = f"  {GRAY}{extra}{RESET}" if extra else ""

        print(f"  {ts_str} {num}  {method_str}  {status_str}  {url_display}{extra_str}")

# ─── Blacklist check ───────────────────────────────────────────────────────────

def is_blacklisted(host: str, url: str, blacklist: list[str]) -> bool:
    host_lower = host.lower()
    url_lower  = url.lower()
    for entry in blacklist:
        entry = entry.strip()
        if not entry:
            continue
        # Entry is a full URL prefix (starts with http://)
        if entry.startswith("http://") or entry.startswith("https://"):
            if url_lower.startswith(entry):
                return True
        else:
            # Entry is a domain — match exact or subdomain
            if host_lower == entry or host_lower.endswith("." + entry):
                return True
    return False

# ─── HTTP parsing ───────────────────────────────────────────────────────────────

def parse_request_line(data: bytes):
    """Return (method, url, version, host, port, path) or None on error."""
    try:
        header_end = data.find(b"\r\n\r\n")
        headers_raw = data[:header_end] if header_end != -1 else data
        first_line_end = headers_raw.find(b"\r\n")
        first_line = headers_raw[:first_line_end].decode("utf-8", errors="replace")
        parts = first_line.split(" ", 2)
        if len(parts) < 3:
            return None
        method, raw_url, version = parts

        parsed = urlparse(raw_url)
        host = parsed.hostname or ""
        port = parsed.port or 80
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        # Try Host header if urlparse gave no host
        if not host:
            for line in headers_raw.split(b"\r\n")[1:]:
                if line.lower().startswith(b"host:"):
                    host_header = line[5:].decode("utf-8", errors="replace").strip()
                    if ":" in host_header:
                        host, p = host_header.rsplit(":", 1)
                        try:
                            port = int(p)
                        except ValueError:
                            pass
                    else:
                        host = host_header
                    break

        return method, raw_url, version, host, port, path
    except Exception:
        return None

def rewrite_request(data: bytes, host: str, port: int, path: str, version: str, method: str) -> bytes:
    """Replace absolute URL with path-only form (RFC 2616 §5.1.2)."""
    try:
        header_end = data.find(b"\r\n\r\n")
        if header_end == -1:
            header_end = len(data)
            body = b""
        else:
            body = data[header_end + 4:]

        headers_raw = data[:header_end]
        lines = headers_raw.split(b"\r\n")
        lines[0] = f"{method} {path} {version}".encode()

        new_lines = [lines[0]]
        for line in lines[1:]:
            if line.lower().startswith(b"proxy-connection:"):
                continue
            new_lines.append(line)

        return b"\r\n".join(new_lines) + b"\r\n\r\n" + body
    except Exception:
        return data

# ─── Build blocked page ─────────────────────────────────────────────────────────

def blocked_response(url: str) -> bytes:
    body = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Access Blocked</title>
<style>
  body {{ font-family: Arial, sans-serif; background: #1a1a2e; color: #eee;
          display: flex; align-items: center; justify-content: center;
          height: 100vh; margin: 0; }}
  .box {{ background: #16213e; border: 2px solid #e94560; border-radius: 12px;
          padding: 40px; text-align: center; max-width: 520px; }}
  h1 {{ color: #e94560; font-size: 2rem; margin-bottom: 10px; }}
  .url {{ background: #0f3460; padding: 10px; border-radius: 6px; margin: 16px 0;
          word-break: break-all; font-family: monospace; color: #a8dadc; }}
  p {{ color: #aaa; line-height: 1.6; }}
</style></head>
<body>
  <div class="box">
    <h1>&#128683; Access Blocked</h1>
    <p>The proxy server has blocked access to this address:</p>
    <div class="url">{url}</div>
    <p>This domain or URL is in the blacklist.<br>
       Contact your administrator if you believe this is a mistake.</p>
  </div>
</body></html>""".encode("utf-8")

    header = (
        "HTTP/1.1 403 Forbidden\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode()
    return header + body

# ─── Client handler ─────────────────────────────────────────────────────────────

def handle_client(client_sock: socket.socket, addr, config: dict, blacklist: list[str]):
    buf_size   = config.get("buffer_size", 4096)
    server_sock = None

    try:
        # Read full request headers
        data = b""
        while True:
            chunk = client_sock.recv(buf_size)
            if not chunk:
                return
            data += chunk
            if b"\r\n\r\n" in data:
                break

        parsed = parse_request_line(data)
        if not parsed:
            return
        method, raw_url, version, host, port, path = parsed

        # Blacklist check
        if is_blacklisted(host, raw_url, blacklist):
            log(method, raw_url, 403, blocked=True)
            client_sock.sendall(blocked_response(raw_url))
            return

        # Connect to destination
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.settimeout(30)
        try:
            server_sock.connect((host, port))
        except Exception as e:
            log(method, raw_url, 502, extra=f"connect error: {e}")
            err_body = f"<h1>502 Bad Gateway</h1><p>Cannot connect to {host}:{port}</p><p>{e}</p>".encode()
            client_sock.sendall(
                f"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/html\r\n"
                f"Content-Length: {len(err_body)}\r\nConnection: close\r\n\r\n".encode() + err_body
            )
            return

        # Forward rewritten request
        rewritten = rewrite_request(data, host, port, path, version, method)
        server_sock.sendall(rewritten)

        # Stream response back
        status_code = None
        first_chunk = True
        total_bytes = 0

        while True:
            try:
                chunk = server_sock.recv(buf_size)
            except socket.timeout:
                break
            if not chunk:
                break

            if first_chunk:
                try:
                    first_line = chunk.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
                    parts = first_line.split(" ", 2)
                    if len(parts) >= 2:
                        status_code = int(parts[1])
                except (ValueError, IndexError):
                    pass
                first_chunk = False

            total_bytes += len(chunk)
            try:
                client_sock.sendall(chunk)
            except (BrokenPipeError, ConnectionResetError):
                break

        extra = f"{total_bytes / 1024:.1f} KB" if total_bytes else ""
        log(method, raw_url, status_code, extra=extra)

    except (ConnectionResetError, BrokenPipeError):
        pass
    except Exception as e:
        print(f"{RED}[ERROR]{RESET} {addr}: {e}")
    finally:
        try:
            client_sock.close()
        except Exception:
            pass
        if server_sock:
            try:
                server_sock.close()
            except Exception:
                pass

# ─── Main ──────────────────────────────────────────────────────────────────────

def run_proxy():
    config    = load_config()
    blacklist = load_blacklist()

    host = config.get("host", "127.0.0.1")
    port = config.get("port", 8080)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(100)

    print()
    print(f"{BOLD}{CYAN}╔══════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║       HTTP Proxy Server  v1.0  (Python)      ║{RESET}")
    print(f"{BOLD}{CYAN}╚══════════════════════════════════════════════╝{RESET}")
    print(f"  {GREEN}●{RESET} Listening   {BOLD}{host}:{port}{RESET}")
    print(f"  {YELLOW}●{RESET} Blacklist   {len(blacklist)} entries  ({BLACKLIST_FILE})")
    print(f"  {CYAN}●{RESET} Config      {CONFIG_FILE}")
    print()
    print(f"  Set browser HTTP proxy to:  {BOLD}{host}  port {port}{RESET}")
    print()
    print(f"{GRAY}  {'Time':^10}  {'#':^6}  {'Method':<8}  {'Status':<8}  URL{RESET}")
    print(f"{GRAY}  {'─'*10}  {'─'*6}  {'─'*8}  {'─'*8}  {'─'*50}{RESET}")

    try:
        while True:
            client_sock, addr = srv.accept()
            t = threading.Thread(
                target=handle_client,
                args=(client_sock, addr, config, blacklist),
                daemon=True
            )
            t.start()
    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}[INFO]{RESET} Proxy stopped. Requests served: {request_count}")
    finally:
        srv.close()

if __name__ == "__main__":
    run_proxy()
