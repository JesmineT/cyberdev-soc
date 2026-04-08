# SIEM (Security Information and Event Management) is a software solution 
# that improves threat detection, investigation, and response by
# providing real-time visibility across an organization's IT infrastructure.
# It aggregates logs from diverse sources, uses AI/analytics to identify anomalies, 
# and automates responses to security incidents.
from dotenv import load_dotenv
load_dotenv()  # Load environment variables from .env file

from chain import run_incident_chain
import asyncio
import json


async def main():
    # load alert
    print("CyberDev SOC - Agentic Incident Response")
    print("=" * 50)

    with open("sample_alert.json", "r") as f:
        alert = json.load(f)

    print(f"\nAlert received: {alert['alert_id']}")
    print(f"Target: {alert['hostname']}")
    print(f"Source IP: {alert['source_ip']}")
    print(f"Event: {alert['event_type']}")
    print("\n" + "=" * 50)

    # run the chain
    report = await run_incident_chain(alert)

    # save report
    with open("incident_report.json", "w") as f:
        json.dump(report.model_dump(), f, indent=4)

    # Print Report
    print("\n" + "=" * 50)
    print("📋 INCIDENT REPORT")
    print("=" * 50)
    print(f"\nSeverity: {report.severity}")
    print(f"\nExecutive Summary:\n{report.executive_summary}")
    print(f"\nInvestigation Findings:\n{report.investigation_findings}")
    print(f"\nMITRE Mapping:\n{report.mitre_mapping}")
    print(f"\nContainment Actions:")
    for i, action in enumerate(report.containment_actions, 1):
        print(f"   {i}. {action}")
    print(f"\nTimeline:")
    for event in report.timeline:
        print(f"   → {event}")
    print("\nFull report saved to incident_report.json")
    print("=" * 50)

if __name__ == "__main__":
    asyncio.run(main())
