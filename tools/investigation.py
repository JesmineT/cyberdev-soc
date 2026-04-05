import pydantic

# async function but currently no await because it's just returning mock data. 
# In production, these would likely involve async calls to databases or external APIs.


# Checks if an IP is malicious, part of TOR, or has abuse history
@agent.tool
async def lookup_ip_reputation(ctx: RunContext, ip: str) -> dict:
    """Looks up the reputation of an IP address. 
    Use this to check if a source IP is known malicious, 
    part of tor, or has abuse reports.
    e.g. ip = 185.220.101.45
    """
    mock_data = {
        "185.220.101.45": {
            "reputation": "malicious",
            "known_tor_exit": True,
            "abuse_reports": 142,
            "country": "Singapore",
            "tags": ["tor", "scanner", "brute-force"]
        }
    }

    return mock_data.get(ip, {"reputation": "unknown"})

# Finds where an IP is physically located and if it's using VPN/proxy
@agent.tool
async def get_geolocation(ctx: RunContext, ip: str) -> dict:
    """Gets the geolocation information for a given IP address. 
    Use this to understand where an IP address is located, which can provide context for its activity.
    e.g. ip = "185.220.101.45"
    """
    mock_data = {
        "185.220.101.45": {
            "country": "Singapore",
            "region": "Central Singapore",
            "city": "Singapore",
            "latitude": 1.3521,
            "longitude": 103.8198,
            "isp": "OVH SAS",
            "is_vpn": True,
            "is_proxy": True,
            "is_datacenter": True,
            "risk_score": 85
        }
    }
    return mock_data.get(ip, {"country": "unknown"})

# Identifies if an IP/domain/hash is linked to known APT groups like APT28
@agent.tool
async def get_threat_intel(ctx: RunContext, indicator: str) -> dict:
    """Gets threat intelligence for a given indicator (IP, domain, hash). 
    Use this to enrich your understanding of an indicator's potential maliciousness.
    e.g. indicator = "185.220.101.45", indicator_type = "ip"
    """
    mock_data = { 
        "185.220.101.45": {
            "threat_actor": "APT28",
            "campaign": "Fancy Bear",
            "target_sectors": ["government", "military"],
            "first_seen": "2021-05-12",
            "last_seen": "2024-06-01",
            "confidence": "high"
        }
    }

    return mock_data.get(indicator, {"threat_actor": "unknown"})

