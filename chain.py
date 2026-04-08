import asyncio
import json
from agents import triage_agent, investigation_agent, report_agent
import tools # triggers all tool registrations from __init__.py

async def run_incident_chain(alert: dict) -> str: # takes dict parameter and returns a string
    alert_str = json.dumps(alert, indent=2) # converts python dict into a formatted json string so can be passed to claude inside a prompt

    # step 1: triage
    print("\n[1/3] Running Triage Agent...")
    triage_result = await triage_agent.run(
        f"Triage this security alert:\n{alert_str}"
    )

    triage = triage_result.output
    print(f":D Triage complete - Severity: {triage.severity} | True Positive: {triage.is_true_positive}")

    # step 2: investigation
    print("\n[2/3] Running Investigation Agent...")
    investigation_result = await investigation_agent.run(
        f"""
        Original Alert: {alert_str}

        Triage Findings:
        - Severity: {triage.severity}
        - Attack Type: {triage.attack_type}
        - Source IP: {triage.source_ip}
        - Affected Host: {triage.affected_host}
        - Reasoning: {triage.reasoning}

        Perform a deeper investigation now.
        """
    )

    investigation = investigation_result.output
    print(f"Investigation complete - Threat Actor: {investigation.threat_actor} | Nation State: {investigation.is_nation_state}")

    # Step 3: report
    print("\n[3/3] Running Report Agent...")
    report_result = await report_agent.run(
        f"""
        Original Alert: {alert_str}

        Triage Findings:
        - Severity: {triage.severity}
        - Attack Type: {triage.attack_type}
        - Source IP: {triage.source_ip}
        - Affected Host: {triage.affected_host}
        - Confidence: {triage.confidence_score}
        - Reasoning: {triage.reasoning}

        Investigation Findings:
        - Timeline: {triage.timeline if hasattr(triage, 'timeline') else 'N/A'}
        - MITRE Tactic: {investigation.mitre_tactic}
        - MITRE Technique: {investigation.mitre_technique}
        - Threat Actor: {investigation.threat_actor}
        - Blast Radius: {investigation.blast_radius}
        - Nation State: {investigation.is_nation_state}
        - Summary: {investigation.summary}

        Generate a full professional incident report.
        """
    )
    report = report_result.output
    print("✅ Report generated.")

    return report


if __name__ == "__main__":
    asyncio.run(run_incident_chain({}))


# In Pydantic AI, when you call agent.run() it returns an AgentRunResult object.
# The actual structured output you defined in output_type lives inside .output:

# result = await triage_agent.run("...")
# result                  # AgentRunResult object
# result.output           # TriageResult object ← this is what you want
# result.output.severity  # "CRITICAL"
# result.output.is_true_positive  # True