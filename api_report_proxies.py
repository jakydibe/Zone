#!/usr/bin/env python3
"""
Submit all .bin files in a directory (and subdirectories) to VirusTotal
asynchronously with multiple API keys, rotating to a different proxy/IP
every N file submissions.

Requires: pip install vt-py aiohttp
"""

import os
import json
import asyncio
import time
import vt
from typing import List, Set
import aiohttp



# ──────────── Configuration ──────────────────────────────────────────
API_KEYS_FILE        = "api_keys.txt"
PROXIES_FILE         = "proxies.txt"        #  ← NEW
PROXY_ROTATE_EVERY   = 30                   #  ← NEW
PORXY_ROTATE_EVERY_MINUTE = 5                #  ← NEW
PROCESSED_FILE       = "processed_files.json"
RESULTS_FILE         = "results.json"
CONCURRENCY          = 30
MUTATIONS_DIRECTORY  = "mutations/mutations"

maximum_errors = 100
# ──────────────────────────────────────────────────────────────────────


def set_proxy_env(proxy_url: str | None) -> None:
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        if proxy_url:
            os.environ[var] = proxy_url
        else:
            os.environ.pop(var, None)



async def load_json_set(path: str) -> Set[str]:
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                return set(json.load(f))
        except (ValueError, json.JSONDecodeError):
            return set()
    return set()


async def proxy_alive(url: str | None, timeout=10) -> bool:
    """Return True if the proxy (or direct) can reach VirusTotal."""
    try:
        connector = aiohttp.TCPConnector(ssl=False, trust_env=True)
        async with aiohttp.ClientSession(connector=connector) as sess:
            async with sess.head(
                "https://www.virustotal.com", proxy=url,
                timeout=timeout
            ):
                return True
    except Exception:
        return False


async def load_json_list(path: str) -> list:
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                return json.load(f)
        except (ValueError, json.JSONDecodeError):
            return []
    return []


async def save_json(path: str, data) -> None:
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


class APIKeyClient:
    def __init__(self, api_key: str):
        self.api_key = api_key


        # trust_env=True lets aiohttp pick up HTTP_PROXY/HTTPS_PROXY
        self.client  = vt.Client(api_key, trust_env=True)
        self.remaining_quota = 0

    async def validate(self) -> bool:
        global maximum_errors

        try:
            data = await self.client.get_json_async(
                f"/users/{self.api_key}/overall_quotas"
            )
            user = data["data"]["api_requests_daily"]["user"]
            self.remaining_quota = user["allowed"] - user["used"]
            return True
        except Exception as e:
            maximum_errors -= 1
            if maximum_errors <= 0:
                print(f"[ERROR] API key {self.api_key} is invalid: {e}")
                exit(1)

            print(f"[ERROR] API key {self.api_key}: {e}")
            return False          # ← don’t exit; just signal failure

    async def update_quota(self) -> int:
        global maximum_errors

        try:
            data = await self.client.get_json_async(
                f"/users/{self.api_key}/overall_quotas"
            )
            user = data["data"]["api_requests_daily"]["user"]
            self.remaining_quota = user["allowed"] - user["used"]
        except Exception as e:
            maximum_errors -= 1
            if maximum_errors <= 0:
                print(f"[ERROR] API key {self.api_key} is invalid: {e}")
                exit(1)
            print(f"[ERROR] Quota fetch failed for {self.api_key}: {e}")
            self.remaining_quota = 0
        return self.remaining_quota

    async def scan_file(self, file_path: str):
        with open(file_path, 'rb') as f:
            analysis = await self.client.scan_file_async(
                f, wait_for_completion=True
            )
        return analysis


async def process_file(file_path: str,
                       clients: List[APIKeyClient],
                       processed: set,
                       results: list,
                       sem: asyncio.Semaphore):
    async with sem:
        if file_path in processed:
            return

        # pick first client with quota
        client = None
        for c in clients:
            await c.update_quota()
            if c.remaining_quota > 0:
                client = c
                break
        if not client:
            maximum_errors -= 1
            if maximum_errors <= 0:
                print(f"[ERROR] All API keys exhausted for {file_path}.")
                exit(1)
            print("[WARN] All API quotas exhausted for this batch.")
            return

        try:
            analysis = await client.scan_file(file_path)
            stats = analysis.stats
            malicious = stats.get("malicious", 0)
            total     = sum(stats.values())
            print(f"{file_path}: {malicious}/{total}")

            processed.add(file_path)
            results.append({
                "file": file_path,
                "malicious": malicious,
                "total_scans": total,
                "date": time.strftime("%Y-%m-%dT%H:%M:%S")
            })
            await save_json(PROCESSED_FILE, list(processed))
            await save_json(RESULTS_FILE,   results)
        except Exception as e:
            print(f"[ERROR] {file_path} -> {e}")


async def create_clients(keys: list[str]) -> list[APIKeyClient]:
    usable = []
    for key in keys:
        client = APIKeyClient(key)
        if await client.validate() and client.remaining_quota > 0:
            usable.append(client)
        else:
            # close immediately ➜ no “unclosed connector” warnings
            try:
                await client.client.close_async()
            except Exception:
                pass
    return usable



async def close_clients(clients: List[APIKeyClient]) -> None:     # ← NEW
    for c in clients:
        try:
            await c.client.close_async()
        except Exception:
            pass


async def main():
    # Ensure persistence files exist
    for fn in (PROCESSED_FILE, RESULTS_FILE):
        if not os.path.exists(fn):
            with open(fn, "w") as f:
                f.write("[]")

    # Load API keys
    if not os.path.exists(API_KEYS_FILE):
        print(f"API keys file not found: {API_KEYS_FILE}")
        return
    with open(API_KEYS_FILE) as f:
        keys = [line.strip() for line in f if line.strip()]
    if not keys:
        print("No API keys!")
        return

    # Load proxy list  (empty list ⇒ no rotation, direct connection)
    proxies = []
    if os.path.exists(PROXIES_FILE):
        with open(PROXIES_FILE) as f:
            proxies = [p.strip() for p in f if p.strip()]
    checked = []
    for p in proxies or [None]:
        if await proxy_alive(p):
            checked.append(p)
        else:
            print(f"[WARN] proxy {p or 'direct'} is unreachable – skipped.")
    proxies = checked or [None]        # always have something to use

    processed = await load_json_set(PROCESSED_FILE)
    results   = await load_json_list(RESULTS_FILE)

    # Gather .bin files
    all_files = []
    for root, _, fnames in os.walk(MUTATIONS_DIRECTORY):
        for fn in fnames:
            if fn.lower().endswith(".bin"):
                fp = os.path.abspath(os.path.join(root, fn))
                if fp not in processed:            # skip already done
                    all_files.append(fp)

    if not all_files:
        print("Nothing new to submit.")
        return

    # ───────────── Batch loop with proxy rotation ─────────────
    start_time = time.time()
    for batch_idx, start in enumerate(range(0, len(all_files), PROXY_ROTATE_EVERY)):

        end          = start + PROXY_ROTATE_EVERY
        batch_files  = all_files[start:end]
        proxy_url    = proxies[batch_idx % len(proxies)]
        set_proxy_env(proxy_url)                   # ← NEW
        if proxy_url:
            print(f"\n[INFO] ► Using proxy {proxy_url}")
        else:
            print(f"\n[INFO] ► Direct connection (no proxy)")

        clients = await create_clients(keys)       # ← NEW
        if not clients:
            print("No usable API keys for this batch. Aborting.")
            return

        sem   = asyncio.Semaphore(CONCURRENCY)
        tasks = [asyncio.create_task(
                    process_file(fp, clients, processed, results, sem)
                 ) for fp in batch_files]
        await asyncio.gather(*tasks)

        await close_clients(clients)               # ← NEW
        print(f"[INFO] ▲ Completed batch {batch_idx+1} "
              f"({len(batch_files)} files)")

    print("\n[DONE] All pending files processed.")


if __name__ == "__main__":
    asyncio.run(main())
