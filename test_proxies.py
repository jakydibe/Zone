import asyncio, aiohttp, pathlib

PROXY_FILE = "proxies.txt"
TEST_URL   = "https://www.virustotal.com/"

async def probe(proxy):
    try:
        async with aiohttp.ClientSession() as s:
            async with s.head(TEST_URL, proxy=proxy, timeout=10):
                return proxy, "OK"
    except Exception as e:
        return proxy, f"{type(e).__name__}: {e}"

async def main():
    proxies = [p.strip() for p in pathlib.Path(PROXY_FILE).read_text().splitlines() if p.strip()]
    results = await asyncio.gather(*(probe(p if "://" in p else f"http://{p}") for p in proxies))
    for p, r in results:
        # print(f"{p:<35} -> {r}")
        if r == "OK":
            print(f"{p}")

asyncio.run(main())
