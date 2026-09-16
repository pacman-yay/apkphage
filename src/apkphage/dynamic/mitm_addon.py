import ipaddress
import json
import os

from mitmproxy import ctx, http

# The path where the JSON dump will be saved inside the container
DUMP_FILE = os.getenv("MITM_DUMP_FILE", "/work/traffic.json")
# Mode: "fakenet" or "tor"
NETWORK_MODE = os.getenv("NETWORK_MODE", "fakenet")


class APKPhageAddon:
    def __init__(self):
        self.flows_data = []

    def request(self, flow: http.HTTPFlow):
        # 1. Block LAN access if in Tor mode to protect the host
        if NETWORK_MODE == "tor":
            host = flow.request.host
            try:
                ip = ipaddress.ip_address(host)
                if ip.is_private:
                    ctx.log.warn(f"[!] Blocked private IP request to {host}")
                    flow.kill()
                    return
            except ValueError:
                pass  # It's a hostname, not an IP. DNS resolution happens later.

    def response(self, flow: http.HTTPFlow):
        # 2. Record the flow data for the report
        try:
            req = flow.request
            res = flow.response

            flow_dict = {
                "url": req.url,
                "method": req.method,
                "host": req.host,
                "status_code": res.status_code if res else 0,
                "request_headers": dict(req.headers),
                "response_headers": dict(res.headers) if res else {},
            }

            # Save simple content if it's text/json
            content_type = res.headers.get("content-type", "") if res else ""
            if "text" in content_type or "json" in content_type:
                try:
                    flow_dict["response_body"] = res.content.decode("utf-8")[:1000]  # Limit size
                except UnicodeDecodeError:
                    pass

            self.flows_data.append(flow_dict)
        except Exception as e:
            ctx.log.error(f"Error parsing flow: {e}")

    def done(self):
        # 3. Write out the final JSON file when mitmproxy shuts down
        try:
            with open(DUMP_FILE, "w") as f:
                json.dump(self.flows_data, f, indent=2)
            ctx.log.info(f"[+] Traffic JSON saved to {DUMP_FILE}")
        except Exception as e:
            ctx.log.error(f"Failed to save traffic JSON: {e}")


addons = [APKPhageAddon()]
