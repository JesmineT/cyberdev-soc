# async function but currently no await because it's just returning mock data. 
# In production, these would likely involve async calls to databases or external APIs.

# Pulls recent log entries from a host to find suspicious activity

from pydantic_ai import RunContext


from agents import investigation_agent

@investigation_agent.tool
async def search_logs(ctx: RunContext, hostname: str, timeframe_minutes: int) -> list:
    """Searches logs for a given hostname within a specified timeframe. 
    Use this to find relevant log entries that may indicate malicious activity.
    e.g. hostname = "server1", timeframe_minutes = 60
    """
    return [
        {"time": "03:21:50", "event": "Failed SSH login for root"},
        {"time": "03:22:01", "event": "Failed SSH login for admin"},
        {"time": "03:22:43", "event": "847 failed attempts detected"}    
    ]

# Checks a user's login history and flags unusual patterns
@investigation_agent.tool
async def get_user_behavior(ctx: RunContext, username: str) -> dict:
    """
    Gets recent behavior patterns for a given username. 
    Use this to identify any unusual activity that may indicate a compromised account.
    e.g. username = "admin"
    """
    return {
        "username": username,
        "last_login": "2024-06-01 14:32:10",
        "login_locations": ["Singapore", "Germany"],
        "failed_logins": 5,
        "unusual_activity": True
    }

# Rates how critical a host is to the business if compromised
@investigation_agent.tool
async def check_asset_criticality(ctx: RunContext, hostname:str) -> dict:
    """Checks the criticality of an asset based on its hostname. 
    Use this to prioritize your response based on how critical the asset is to your operations.
    e.g. hostname = "server1"
    """
    mock_data = {
        "server1": {
            "criticality": "high",
            "business_impact": "loss of customer data",
            "recovery_time_objective": "4 hours"
        }
    }

    return mock_data.get(hostname, {"criticality": "unknown"})
