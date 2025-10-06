# Agent Orchestration for Cloud Architecture Planning
# Format: Problem statement + Written response

"""
AGENT ORCHESTRATION CHALLENGE

You need to design a multi-agent system that can analyze business problems and recommend 
cloud architecture solutions. Focus on the orchestration strategy, not implementation details.

SAMPLE SCENARIOS (choose 2 to address):

1. "Simple E-commerce Site"
   - Online store for small business (1000 daily users)
   - Product catalog, shopping cart, payment processing
   - Basic admin dashboard for inventory management

2. "Customer Support Chatbot"
   - AI chatbot for customer service 
   - Integration with existing CRM system
   - Handle 500+ conversations per day
   - Escalate complex issues to human agents

3. "Employee Expense Tracker"
   - Mobile app for expense reporting
   - Receipt photo upload and processing
   - Approval workflow for managers
   - Integration with payroll system

YOUR TASK:
Design an agent orchestration approach that can take these problems and output 
a cloud architecture recommendation including basic services needed (database, 
API gateway, compute, storage, etc.).
"""

# Your Code Here

"""
agent_orchestration_cloud_planner.py

A runnable simulation of a multi-agent orchestration system that:
- Accepts a scenario/problem statement
- Agents extract requirements, map to cloud resources, estimate cost & compliance,
  validate integrations, and produce a final recommended architecture.

This is a simulation — no external network calls or secrets are used.
The code is modular so you can replace internal heuristics with real models/APIs.
"""

import json
import logging
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional, Tuple
import random

# ---------- Logging ----------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Orchestrator")

# ---------- Data structures ----------
@dataclass
class RequirementSummary:
    functional: List[str] = field(default_factory=list)
    non_functional: List[str] = field(default_factory=list)
    expected_load: Dict[str, Any] = field(default_factory=dict)
    compliance: List[str] = field(default_factory=list)
    integrations: List[str] = field(default_factory=list)
    extras: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ArchitectureProposal:
    services: Dict[str, Any] = field(default_factory=dict)
    justification: Dict[str, str] = field(default_factory=dict)
    estimated_monthly_cost: Optional[float] = None
    compliance_flags: List[str] = field(default_factory=list)
    risks: List[str] = field(default_factory=list)
    confidence: float = 0.0  # 0..1

# ---------- Agents ----------
class RequirementsAnalyst:
    """
    Parses text scenario into structured requirements. (Heuristic-based for demo.)
    """
    def analyze(self, scenario: Dict[str, Any]) -> RequirementSummary:
        logger.info("RequirementsAnalyst: analyzing scenario")
        summary = RequirementSummary()
        desc = scenario.get("description", "").lower()

        # Functional: from scenario keys
        for key in ["product catalog", "shopping cart", "payment", "chatbot", "receipt", "approval workflow"]:
            if key in desc:
                summary.functional.append(key)

        # Add scenario-specific lines
        if "payment" in desc or "payment processing" in desc:
            summary.functional.append("payment_processing")
            summary.compliance.append("PCI-DSS")

        if "chatbot" in desc:
            summary.functional.append("nlp_chatbot")
            summary.non_functional.append("low_latency")

        # Basic load estimate heuristics
        users = scenario.get("users_daily")
        if users:
            summary.expected_load["daily_users"] = users
            # estimate concurrent
            summary.expected_load["concurrent_peak"] = max(1, int(users * 0.01))

        # Attach integrations if mentioned
        if "crm" in desc:
            summary.integrations.append("crm")

        if "payroll" in desc:
            summary.integrations.append("payroll")

        # File uploads
        if "receipt" in desc or "images" in desc:
            summary.functional.append("file_uploads")
            summary.non_functional.append("durable_storage")

        # Admin dashboard
        if "admin" in desc:
            summary.functional.append("admin_dashboard")
            summary.non_functional.append("role_based_access")

        # Add extras
        summary.extras.update(scenario.get("extras", {}))

        logger.debug("Requirements summary: %s", summary)
        return summary


class CloudSolutionMapper:
    """
    Maps requirements into a candidate architecture proposal.
    """
    def map(self, req: RequirementSummary) -> ArchitectureProposal:
        logger.info("CloudSolutionMapper: mapping requirements -> services")
        p = ArchitectureProposal()
        services = {}

        # Compute choices
        if "nlp_chatbot" in req.functional:
            services["compute"] = {
                "type": "containers + managed inference",
                "options": ["ECS/Fargate + hosted LLM inference", "or serverless functions for glue"]
            }
            p.justification["compute"] = "Chatbot requires persistent model serving and moderate CPU/RAM."
            p.confidence += 0.2
        elif req.expected_load.get("daily_users", 0) <= 2000:
            services["compute"] = {"type": "serverless", "options": ["AWS Lambda / Azure Functions / GCP Cloud Functions"]}
            p.justification["compute"] = "Low-to-medium traffic; serverless reduces ops effort and cost."
            p.confidence += 0.15
        else:
            services["compute"] = {"type": "containers", "options": ["Kubernetes/EKS or ECS Fargate"]}
            p.justification["compute"] = "Higher traffic expected; containers allow scaling and long-running processes."
            p.confidence += 0.15

        # Database choices
        if "payment_processing" in req.functional:
            services["database"] = {"type": "relational", "options": ["RDS/Postgres"], "reason": "ACID for orders/payments"}
            p.confidence += 0.15
        else:
            services["database"] = {"type": "managed_document_or_relational", "options": ["RDS/Postgres", "DynamoDB (NoSQL)"], "reason": "Flexibility"}
            p.confidence += 0.1

        # Storage for files
        if "file_uploads" in req.functional or "durable_storage" in req.non_functional:
            services["object_storage"] = {"type": "S3-compatible", "options": ["S3/GCS/Azure Blob"], "reason": "Store images, receipts, static assets"}
            p.confidence += 0.05

        # Networking and CDN
        services["api_gateway"] = {"type": "managed_api_gateway", "reason": "Routing, auth, rate-limiting"}
        services["cdn"] = {"type": "edge_cdn", "options": ["CloudFront / Cloud CDN"], "reason": "Cache static assets and speed up global access"}
        p.confidence += 0.05

        # Security and observability
        services["auth"] = {"type": "managed_idp", "options": ["Cognito / Auth0 / Azure AD B2C"], "reason": "Role-based access for admin dashboard"}
        services["monitoring"] = {"type": "logging_and_metrics", "options": ["CloudWatch / Stackdriver / Azure Monitor"], "reason": "Alerts and dashboards"}
        services["waf"] = {"type": "web_application_firewall", "reason": "Protect public endpoints"}
        p.confidence += 0.1

        # Integration connectors
        if req.integrations:
            services["integration"] = {"connectors": req.integrations, "pattern": "API gateway + secure connectors"}
            p.confidence += 0.05

        p.services = services

        # Simple risk enumeration
        p.risks = []
        if "PCI-DSS" in req.compliance:
            p.compliance_flags.append("PCI-DSS")
            p.risks.append("Requires strict cardholder data handling and audit readiness")
            p.confidence += 0.05

        # Short justification per component created above (already partially filled)
        if "database" not in p.justification and "database" in services:
            p.justification["database"] = services["database"].get("reason", "Managed DB for persistence")

        # Base cost estimate (heuristic)
        base_cost = 20.0  # base for small infra
        users = req.expected_load.get("daily_users", 100)
        base_cost += (users / 1000.0) * 50.0
        if services.get("compute", {}).get("type") == "containers":
            base_cost += 150.0
        if "nlp_chatbot" in req.functional:
            base_cost += 300.0  # inference costs
        p.estimated_monthly_cost = round(base_cost + random.uniform(-10, 20), 2)

        logger.debug("Architecture proposal: %s", p)
        return p


class CostAndComplianceEvaluator:
    """
    Evaluates cost, suggests cheaper alternatives, and flags compliance issues.
    """
    def evaluate(self, proposal: ArchitectureProposal) -> ArchitectureProposal:
        logger.info("CostAndComplianceEvaluator: evaluating costs and compliance")
        # If cost too high, suggest cost-saving measures:
        if proposal.estimated_monthly_cost and proposal.estimated_monthly_cost > 300:
            proposal.justification["cost_optimization"] = "Consider reserved instances, switching some workloads to serverless, or smaller DB instance tiers."
            proposal.estimated_monthly_cost = round(proposal.estimated_monthly_cost * 0.75, 2)
            proposal.confidence -= 0.05

        # If PCI required, add notes
        if "PCI-DSS" in proposal.compliance_flags:
            proposal.justification["pci"] = "Use tokenization, never store card PANs. Use hosted payment pages/third-party gateways."
            proposal.confidence += 0.05

        # Add monitoring for compliance
        proposal.justification["audit"] = "Enable detailed logs and retention for compliance audits."

        logger.debug("Post-evaluation proposal: %s", proposal)
        return proposal


class IntegrationCoordinator:
    """
    Ensures integrations and dataflows are consistent and creates integration notes.
    """
    def validate(self, proposal: ArchitectureProposal, req: RequirementSummary) -> Tuple[ArchitectureProposal, List[str]]:
        logger.info("IntegrationCoordinator: validating integration points")
        notes = []
        # Validate connectors
        if req.integrations:
            for integ in req.integrations:
                # Basic compatibility heuristics
                notes.append(f"Ensure secure API access to {integ} (OAuth2 or API key + network controls).")

        # Dataflow: ensure backups are present if object storage used
        if "object_storage" in proposal.services:
            notes.append("Enable versioning and lifecycle policies for object storage to limit costs and enable recovery.")

        # Add notes to proposal
        if notes:
            if "integration_notes" not in proposal.justification:
                proposal.justification["integration_notes"] = "; ".join(notes)
            else:
                proposal.justification["integration_notes"] += "; " + "; ".join(notes)

        proposal.confidence += 0.02 * len(notes)
        return proposal, notes


# ---------- Orchestration Manager ----------
class OrchestrationManager:
    """
    Controls agent execution, merging results, conflict resolution, and final output.
    """
    def __init__(self):
        self.req_agent = RequirementsAnalyst()
        self.mapper = CloudSolutionMapper()
        self.cost_eval = CostAndComplianceEvaluator()
        self.integration = IntegrationCoordinator()

    def process(self, scenario: Dict[str, Any]) -> Dict[str, Any]:
        logger.info("OrchestrationManager: starting orchestration for scenario '%s'", scenario.get("name"))
        # Step 1: Requirements analysis
        req_summary = self.req_agent.analyze(scenario)

        # detect incomplete scenario (simple heuristic)
        if not req_summary.functional and not req_summary.expected_load:
            logger.warning("Input looks incomplete. Filling defaults.")
            # Fill defaults and annotate
            req_summary.functional.append("basic_api")
            req_summary.expected_load["daily_users"] = scenario.get("users_daily", 100)

        # Step 2: Map to cloud solution
        proposal = self.mapper.map(req_summary)

        # Step 3: Cost & compliance evaluation
        proposal = self.cost_eval.evaluate(proposal)

        # Step 4: Integration validation
        proposal, integration_notes = self.integration.validate(proposal, req_summary)

        # Step 5: Finalize (conflict resolution & checks)
        # Example conflict resolution: if both serverless and containers suggested, produce hybrid plan
        compute_type = proposal.services.get("compute", {}).get("type", "")
        if compute_type == "serverless" and "nlp_chatbot" in req_summary.functional:
            # conflict: chatbot usually not purely serverless
            proposal.risks.append("Chatbot may require persistent inference - consider containers or managed inference.")
            proposal.justification["compute_adjustment"] = "Use containers or managed inference for chatbot workloads."
            proposal.confidence -= 0.1

        # Final packaging
        result = {
            "scenario_name": scenario.get("name"),
            "requirement_summary": asdict(req_summary),
            "proposal": {
                "services": proposal.services,
                "justification": proposal.justification,
                "estimated_monthly_cost": proposal.estimated_monthly_cost,
                "compliance_flags": proposal.compliance_flags,
                "risks": proposal.risks,
                "confidence": proposal.confidence,
            },
            "integration_notes": integration_notes
        }

        logger.info("OrchestrationManager: completed with confidence=%.2f", proposal.confidence)
        return result


# ---------- Example scenarios and runner ----------
def example_scenarios() -> List[Dict[str, Any]]:
    return [
        {
            "name": "Simple E-commerce Site",
            "description": "Online store for small business. Product catalog, shopping cart, payment processing, admin dashboard",
            "users_daily": 1000,
            "extras": {}
        },
        {
            "name": "Customer Support Chatbot",
            "description": "AI chatbot for customer service integrated with existing CRM. Handle 500+ conversations per day. Escalate complex issues to human agents.",
            "users_daily": 600,
            "extras": {}
        },
        {
            "name": "Employee Expense Tracker",
            "description": "Mobile app for expense reporting with receipt photo upload, approval workflow and payroll integration.",
            "users_daily": 200,
            "extras": {}
        }
    ]


def run_demo():
    manager = OrchestrationManager()
    scenarios = example_scenarios()
    outputs = []
    for s in scenarios:
        out = manager.process(s)
        outputs.append(out)
        print("=" * 80)
        print(f"Scenario: {out['scenario_name']}")
        print(json.dumps(out, indent=2))
    return outputs


# ---------- If run as main script ----------
if __name__ == "__main__":
    run_demo()


# === WRITTEN RESPONSE QUESTIONS ===

"""
QUESTION 1: AGENT DESIGN (20 points)
What agents would you create for this orchestration? Describe:
- 3-5 specific agents and their roles
- How they would collaborate on the sample problems
- What each agent's input and output would be

Example format:
Agent Name: Requirements Analyst
Role: Break down business requirements into technical needs
Input: Problem description + business context
Output: List of functional requirements, expected load, compliance needs

QUESTION 2: ORCHESTRATION WORKFLOW (25 points)
For ONE of the sample scenarios, walk through your complete workflow:
- Step-by-step process from problem statement to final recommendation
- How agents hand off information to each other
- What happens if an agent fails or produces unclear output
- How you ensure the final solution is complete and feasible

QUESTION 3: CLOUD RESOURCE MAPPING (20 points)
For your chosen scenario, what basic cloud services would your system recommend?
- Compute (serverless functions, containers, VMs)
- Storage (databases, file storage, caching)
- Networking (API gateways, load balancers, CDN)
- Security and monitoring basics
- Justify why each service fits the requirements

QUESTION 4: REUSABILITY & IMPROVEMENT (15 points)
How would you make this system work across different projects?
- What would you standardize vs. customize per project?
- How would the system learn from previous recommendations?
- What feedback mechanisms would improve future solutions?

QUESTION 5: PRACTICAL CONSIDERATIONS (20 points)
What challenges would you expect and how would you handle:
- Conflicting recommendations between agents
- Incomplete or vague problem statements
- Budget constraints not mentioned in requirements
- Integration with existing legacy systems
- Keeping up with new cloud services and pricing
"""