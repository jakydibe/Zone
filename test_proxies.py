from requests_ip_rotator import ApiGateway, EXTRA_REGIONS
import requests, time

# Create a gateway that fronts the target you’re contacting
gateway = ApiGateway("https://virustotal.com", regions=EXTRA_REGIONS)  # ~25 AWS regions → ~25 IPs *
gateway.start()

session = requests.Session()
session.mount("https://virustotal.com", gateway)     # attach the rotator

for i in range(100):
    r = session.get("https://virustotal.com")        # every request leaves via a new IP
    print(i, r.status_code, r.headers.get("x-amz-cf-pop"))
    time.sleep(2)

gateway.shutdown()
