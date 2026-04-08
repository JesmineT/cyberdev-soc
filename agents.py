# 1. Define the Agent objects (triage, investigation, report)
# 2. Give each agent a system prompt (their "job description")
# 3. Define structured output models (what each agent returns)
# 4. Attach the right tools to the right agents

from pydantic import BaseModel
from pydantic_ai import Agent, Tool, RunContext
from typing import List, Optional

class TriageResult(BaseModel):
    is_true_positive: bool
    severity: str # critical, high, medium, low
    attack_type: str
    confidence_score: float # 0.0 to 1.0
    affected_host: str
    source_ip: str
    reasoning: str

class InvestigationResult(BaseModel):
    timeline: List[str]
    mitre_tactic: str
    mitre_technique: str
    threat_actor: str
    blast_radius: str
    is_nation_state: bool
    recommended_severity: str
    summary: str

class IncidentReport(BaseModel):
    executive_summary: str
    alert_details: str
    triage_assessment: str
    investigation_findings: str
    mitre_mapping: str
    containment_actions: List[str]
    timeline: List[str]
    severity: str

# Agents

triage_agent = Agent(
    model="openai:gpt-4o",
    output_type=TriageResult,
    system_prompt="""You are an expert SOC L1 Triage Analyst.
    Your job is to
    1. Determine if an alert is a true positive or false positive
    2. Assign severity: CRITICAL / HIGH / MEDIUM / LOW
    3. Identify attack type (e.g. ransomware, brute-force, data exfiltration)
    4. Check IP reputation and geolocation
    5. Give a confidence score (between 0.0 and 1.0) on your assessment
    
    Always use your tools before making a decision.
    Be precise and concise in your reasoning, and focus on the most relevant information from the alert and tools to make your assessment."""
)

investigation_agent = Agent(
    model="openai:gpt-4o",
    output_type=InvestigationResult,
    system_prompt="""You are an expert SOC L2 Investigation Analyst.
    You receive the triage findings and go deeper:
    1. Search logs and build an attack timeline
    2. Map the attack to MITRE ATT&CK tactics and techniques
    3. Check threat intelligence fr known APT groups
    4. Assess blast radius and potential impact - what else is at risk?
    5. Check if this is a nation state attack
    6. Correlate with other recent alerts to see if it's part of a campaign

    Always use your tools to gather evidence and inform your analysis.
    Be thorough and detailed in your investigation, and focus on building a clear picture of the attack
    """
)

report_agent = Agent(
    model="openai:gpt-4o",
    output_type=IncidentReport,
    system_prompt="""You are an expert SOC L3 Incident Report Writer.
    You receive the triage and investigation findings and write a professional, structured incident report for internal stakeholders and executives.
    Be precise, actionable and professional.
    Your reports are read by both technical teams and executives."""
)