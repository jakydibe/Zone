#!/usr/bin/env python3

"""
Submit all .bin files in a directory (and subdirectories) to VirusTotal asynchronously using multiple API keys,
with quota checking, persistent tracking of processed files and results.
Requires: pip install vt-py
"""
import os
import json
import asyncio
import time
import vt

# Configuration
API_KEYS_FILE      = "api_keys.txt"
PROCESSED_FILE     = "processed_files.json"
RESULTS_FILE       = "results.json"
CONCURRENCY        = 6  # Number of concurrent tasks


users = ['jakyd','jakfu']

MUTATIONS_DIRECTORY = "mutations/mutations"


async def load_json_set(path: str) -> set:
    """
    Load a JSON file at `path` and return its contents as a set.
    If the file does not exist or is empty/invalid, return an empty set.
    """
    if os.path.exists(path):
        try:
            with open(path, 'r') as f:
                return set(json.load(f))
        except (json.JSONDecodeError, ValueError):
            # Empty or invalid JSON
            return set()
    return set()


async def load_json_list(path: str) -> list:
    """
    Load a JSON file at `path` and return its contents as a list.
    If the file does not exist or is empty/invalid, return an empty list.
    """
    if os.path.exists(path):
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, ValueError):
            # Empty or invalid JSON
            return []
    return []


async def save_json(path: str, data) -> None:
    """Save `data` as JSON to `path`, with indentation."""
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)


class APIKeyClient:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.client = vt.Client(api_key)
        self.remaining_quota = 0

    async def validate(self) -> bool:
        try:
            data = await self.client.get_json_async(
                f"/users/{self.api_key}/overall_quotas"
            )
      
            user = data["data"]["api_requests_daily"]["user"]
            self.remaining_quota = user["allowed"] - user["used"]
            print(f"[INFO] API key {self.api_key} has {self.remaining_quota} requests remaining.")
            return True
        except Exception as e:
            print(f"[ERROR] Invalid API key {self.api_key}: {e}")
            return False

    async def update_quota(self) -> int:
        try:
            data = await self.client.get_json_async(
                f"/users/{self.api_key}/overall_quotas"
            )
            user = data["data"]["api_requests_daily"]["user"]
            self.remaining_quota = user["allowed"] - user["used"]
        except Exception as e:
            print(f"[ERROR] Quota fetch failed for {self.api_key}: {e}")
            self.remaining_quota = 0
        return self.remaining_quota

    async def scan_file(self, file_path: str):
        with open(file_path, 'rb') as f:
            analysis = await self.client.scan_file_async(f, wait_for_completion=True)
        return analysis


async def process_file(file_path: str, clients: list, processed: set, results: list, sem: asyncio.Semaphore):
    async with sem:
        if file_path in processed:
            return

        # pick client with available quota
        client = None
        for c in clients:
            await c.update_quota()
            if c.remaining_quota > 0:
                client = c
                break
        if not client:
            print("[WARN] All API quotas exhausted.")
            return

        try:
            analysis = await client.scan_file(file_path)
            stats = analysis.stats
            malicious = stats.get("malicious", 0)
            total = sum(stats.values())
            print(f"{file_path}: {malicious}/{total}")

            processed.add(file_path)
            results.append({
                "file": file_path,
                "malicious": malicious,
                "total_scans": total,
                "date": time.strftime("%Y-%m-%dT%H:%M:%S")
            })
            await save_json(PROCESSED_FILE, list(processed))
            await save_json(RESULTS_FILE, results)
        except Exception as e:
            print(f"[ERROR] {file_path} -> {e}")


async def main():
    # Ensure persistence files exist and contain valid JSON
    for fn, init in [(PROCESSED_FILE, "[]"), (RESULTS_FILE, "[]")]:
        if not os.path.exists(fn):
            with open(fn, "w") as f:
                f.write(init)

    # Load API keys
    if not os.path.exists(API_KEYS_FILE):
        print(f"API keys file not found: {API_KEYS_FILE}")
        return

    with open(API_KEYS_FILE) as f:
        keys = [line.strip() for line in f if line.strip()]

    clients = []
    for key in keys:
        client = APIKeyClient(key)
        if await client.validate() and client.remaining_quota > 0:
            clients.append(client)
        else:
            print(f"Skipping key {key}")

    if not clients:
        print("No valid API keys with quota.")
        return

    try:
        processed = await load_json_set(PROCESSED_FILE)
        results   = await load_json_list(RESULTS_FILE)

        # Enumerate all .bin files
        files = []
        for root, _, fnames in os.walk(MUTATIONS_DIRECTORY):
            for fn in fnames:
                if fn.lower().endswith('.bin'):
                    files.append(os.path.abspath(os.path.join(root, fn)))

        sem = asyncio.Semaphore(CONCURRENCY)
        tasks = [asyncio.create_task(process_file(fp, clients, processed, results, sem)) for fp in files]
        await asyncio.gather(*tasks)

    finally:
        # Always close client sessions
        for c in clients:
            try:
                await c.client.close_async()
            except Exception:
                pass


if __name__ == '__main__':
    asyncio.run(main())