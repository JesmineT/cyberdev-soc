# async function but currently no await because it's just returning mock data. 
# In production, these would likely involve async calls to databases or external APIs.

# Checks if traffic should have been blocked and suggests rules

from pydantic_ai import RunContext


from agents import report_agent

@report_agent.tool
async def check_firewall_rules(ctx: RunContext, source_ip: str, destination_port: int) -> dict:
    """
    Checks existing firewall rules for a given source IP and destination port.
    Use this to determine if the traffic should have been blocked.
    e.g. source_ip = "185.220.101.45", destination_port = 22
    """
    return {
        "rule_exists": False,
        "recommendation": "block",
        "suggested_rule": f"DENY {source_ip} → port {destination_port}",
        "priority": "immediate"
    }

#  Links related alerts together to detect coordinated attacks
@report_agent.tool
async def correlate_alerts(ctx: RunContext, alert_ids: str, timeframe_hours:int) -> list:
    """
    Correlates an alert with other recent alerts within a timeframe to identify patterns.
    Use this to detect coordinated attacks or campaign activity across multiple assets.
    e.g. alert_id = "SOC-2024-001", timeframe_hours = 24
    """
    return [
        {
            "alert_id": "SOC-2024-002",
            "type": "port_scan",
            "source_ip": "185.220.101.45",
            "target": "prod-server-02",
            "time": "02:45:00"
        },
        {
            "alert_id": "SOC-2024-003",
            "type": "brute_force_attempt",
            "source_ip": "185.220.101.45",
            "target": "dc-01",
            "time": "03:10:00"
        }
    ]

# Returns immediate and short term response steps based on severity
@report_agent.tool
async def get_containment_actions(ctx:RunContext, severity:str, attack_type:str) -> dict:
    """
    Gets recommended containment actions based on the severity and type of attack.
    Use this to quickly determine how to respond to an incident based on its characteristics.
    e.g. severity = "high", attack_type = "ransomware"
    """
    actions = {
        "CRITICAL": {
            "immediate": [
                "Isolate affected host from network",
                "Block source IP at perimeter firewall",
                "Revoke all active sessions on affected host",
                "Notify SOC lead and CISO immediately"
            ],
            "short_term": [
                "Force password reset for all accounts on affected host",
                "Enable enhanced logging",
                "Deploy honeypot on affected subnet"
            ],
            "escalate_to_authorities": True
        }
    }
    return actions.get(severity, {"immediate": ["Monitor and log"]})

