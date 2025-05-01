#!/usr/bin/env python3

"""
Submit all .bin files in a directory (and subdirectories) to VirusTotal asynchronously using multiple API keys,
with quota checking, persistent tracking of processed files and results, and rotating through a proxy list.
Requires: pip install vt-py aiohttp
"""
import os
import json
import asyncio
import time
import vt
import aiohttp

# Configuration
API_KEYS_FILE       = "api_keys.txt"
PROXIES_FILE        = "proxies.txt"
PROCESSED_FILE      = "processed_files.json"
RESULTS_FILE        = "results.json"
MUTATIONS_DIRECTORY = "mutations/mutations"
CONCURRENCY         = 15  # Number of concurrent file scans
ROTATE_PROXY_EVERY  = 30  # requests per proxy before rotating
ROTATE_KEY_EVERY    = 1   # requests per API key before rotating


def beep(seconds):
    os.system(f"echo -n '\a'; sleep {seconds}; echo -n '\a'")


async def load_json_set(path: str) -> set:
    if os.path.exists(path):
        try:
            with open(path, 'r') as f:
                return set(json.load(f))
        except (json.JSONDecodeError, ValueError):
            return set()
    return set()


async def load_json_list(path: str) -> list:
    if os.path.exists(path):
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, ValueError):
            return []
    return []


async def save_json(path: str, data) -> None:
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)


async def is_proxy_working(proxy: str) -> bool:
    test_url = "https://www.virustotal.com/"
    timeout = aiohttp.ClientTimeout(total=10)
    proxy_url = f"http://{proxy}" if not proxy.startswith("http") else proxy
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(test_url, proxy=proxy_url) as resp:
                return resp.status == 200
    except Exception:
        return False


class ProxyManager:
    def __init__(self, proxy_file: str, rotate_every: int = ROTATE_PROXY_EVERY):
        self.proxy_file = proxy_file
        self.rotate_every = rotate_every
        self.working = []
        self._index = 0
        self._counter = 0

    async def load_and_verify(self):
        if not os.path.exists(self.proxy_file):
            raise FileNotFoundError(f"Proxy list file not found: {self.proxy_file}")

        with open(self.proxy_file) as f:
            candidates = [line.strip() for line in f if line.strip()]

        sem = asyncio.Semaphore(100)
        async def check(p):
            async with sem:
                if await is_proxy_working(p):
                    self.working.append(p)
        await asyncio.gather(*(check(p) for p in candidates))

        if not self.working:
            raise RuntimeError("No working proxies available")
        print(f"[INFO] {len(self.working)} working proxies loaded.")

    def get_proxy(self) -> str:
        if self._counter >= self.rotate_every:
            self._index = (self._index + 1) % len(self.working)
            self._counter = 0
            print(f"[INFO] Rotated proxy -> {self.working[self._index]}")
        self._counter += 1
        url = self.working[self._index]
        return url if url.startswith("http") else f"http://{url}"


class APIKeyManager:
    """
    Round-robin API key manager that rotates through vt.Clients,
    checking and refreshing quotas as needed.
    """
    def __init__(self, api_keys: list, proxy_mgr: ProxyManager, rotate_every: int = ROTATE_KEY_EVERY):
        self.clients = [APIKeyClient(k, proxy_mgr) for k in api_keys]
        self.rotate_every = rotate_every
        self._index = 0
        self._counter = 0

    async def initialize(self):
        """Validate all keys and filter those with quota."""
        valid = []
        for client in self.clients:
            if await client.validate() and client.remaining_quota > 0:
                valid.append(client)
        if not valid:
            raise RuntimeError("No valid API keys with quota available.")
        self.clients = valid
        print(f"[INFO] {len(self.clients)} API keys ready for rotation.")

    async def get_client(self) -> 'APIKeyClient':
        """
        Return the next client in round-robin with available quota.
        Refresh quotas if needed.
        """
        for attempt in range(len(self.clients)):
            if self._counter >= self.rotate_every:
                self._index = (self._index + 1) % len(self.clients)
                self._counter = 0
                print(f"[INFO] Rotated API key -> {self.clients[self._index].api_key}")
            client = self.clients[self._index]
            await client.update_quota()
            if client.remaining_quota > 0:
                self._counter += 1
                return client
            else:
                # skip exhausted key
                print(f"[WARN] Key {client.api_key} exhausted, skipping.")
                self.clients.pop(self._index)
                if not self.clients:
                    raise RuntimeError("All API keys exhausted.")
                # adjust index if needed
                self._index %= len(self.clients)
        raise RuntimeError("No API key available with quota.")


class APIKeyClient:
    def __init__(self, api_key: str, proxy_mgr: ProxyManager):
        self.api_key = api_key
        self.proxy_mgr = proxy_mgr
        self.remaining_quota = 0

    async def validate(self) -> bool:
        client = vt.Client(self.api_key, proxy=self.proxy_mgr.get_proxy())
        try:
            data = await client.get_json_async(f"/users/{self.api_key}/overall_quotas")
            user = data["data"]["api_requests_daily"]["user"]
            self.remaining_quota = user["allowed"] - user["used"]
            print(f"[INFO] Key {self.api_key} initial quota: {self.remaining_quota}")
            return True
        except Exception as e:
            print(f"[ERROR] Validating key {self.api_key}: {e}")
            return False
        finally:
            await client.close_async()

    async def update_quota(self) -> int:
        client = vt.Client(self.api_key, proxy=self.proxy_mgr.get_proxy())
        try:
            data = await client.get_json_async(f"/users/{self.api_key}/overall_quotas")
            user = data["data"]["api_requests_daily"]["user"]
            self.remaining_quota = user["allowed"] - user["used"]
            return self.remaining_quota
        except Exception as e:
            print(f"[ERROR] Updating quota for {self.api_key}: {e}")
            self.remaining_quota = 0
            return 0
        finally:
            await client.close_async()

    async def scan_file(self, file_path: str):
        client = vt.Client(self.api_key, proxy=self.proxy_mgr.get_proxy())
        try:
            with open(file_path, 'rb') as f:
                return await client.scan_file_async(f, wait_for_completion=True)
        finally:
            await client.close_async()


async def process_file(file_path: str, key_mgr: APIKeyManager, processed: set, results: list, sem: asyncio.Semaphore):
    async with sem:
        if file_path in processed:
            return

        try:
            client = await key_mgr.get_client()
            analysis = await client.scan_file(file_path)
            stats = analysis.stats
            mal = stats.get("malicious", 0)
            tot = sum(stats.values())
            print(f"{file_path}: {mal}/{tot} scans flagged malicious.")

            processed.add(file_path)
            results.append({
                "file": file_path,
                "malicious": mal,
                "total_scans": tot,
                "date": time.strftime("%Y-%m-%dT%H:%M:%S")
            })
            await save_json(PROCESSED_FILE, list(processed))
            await save_json(RESULTS_FILE, results)
        except Exception as e:
            print(f"[ERROR] Scanning {file_path}: {e}")


async def main():
    # initialize persistence files
    for fn, init in [(PROCESSED_FILE, []), (RESULTS_FILE, [])]:
        if not os.path.exists(fn):
            with open(fn, 'w') as f:
                json.dump(init, f)

    # setup proxy manager
    proxy_mgr = ProxyManager(PROXIES_FILE)
    await proxy_mgr.load_and_verify()

    # load and initialize API keys
    if not os.path.exists(API_KEYS_FILE):
        print(f"API keys file missing: {API_KEYS_FILE}")
        return
    with open(API_KEYS_FILE) as f:
        keys = [k.strip() for k in f if k.strip()]

    key_mgr = APIKeyManager(keys, proxy_mgr)
    await key_mgr.initialize()

    # load processed and results
    processed = await load_json_set(PROCESSED_FILE)
    results   = await load_json_list(RESULTS_FILE)

    # gather .bin files
    files = [os.path.abspath(os.path.join(r, fn))
             for r, _, fns in os.walk(MUTATIONS_DIRECTORY)
             for fn in fns if fn.lower().endswith('.bin')]

    sem = asyncio.Semaphore(CONCURRENCY)
    tasks = [asyncio.create_task(process_file(fp, key_mgr, processed, results, sem)) for fp in files]
    await asyncio.gather(*tasks)
    print("[INFO] All done.")

if __name__ == '__main__':
    asyncio.run(main())
