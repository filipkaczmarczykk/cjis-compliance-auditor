from dataclasses import dataclass
from typing import List, Dict, Optional
from enum import Enum

class ComplianceStatus(Enum):
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    MISSING = "missing"
    PENDING_REVIEW = "pending_review"

@dataclass
class CJISRequirement:
    """Individual CJIS requirement with exact policy text"""
    id: str
    section: str
    title: str
    requirement_text: str  # Exact CJIS policy language
    critical: bool = True
    keywords: List[str] = None

@dataclass
class ComplianceCheck:
    """Result of checking one requirement against agency policy"""
    requirement: CJISRequirement
    status: ComplianceStatus
    confidence: float
    evidence_text: str  # Exact text from agency policy
    issues: List[str]
    suggestions: List[str]
    auditor_confirmed: bool = False
    auditor_notes: str = ""

class CJISComplianceChecker:
    """
    Systematic checker that validates agency policies against CJIS requirements.
    Designed for auditor oversight and confirmation workflow.
    """

    def __init__(self):
        self.cjis_requirements = self._load_cjis_requirements()
        self.llm_client = None  # Initialize when ready

    def _load_cjis_requirements(self) -> Dict[str, List[CJISRequirement]]:
        """Load all CJIS requirements organized by section"""
        return {
            "authenticator_management": [
                CJISRequirement(
                    id="5.6.3.2.1",
                    section="5.6.3.2",
                    title="Define Initial Authenticator Content",
                    requirement_text="Agencies shall define initial authenticator content for authenticators defined by the organization.",
                    keywords=["initial", "authenticator", "content", "define", "organization"]
                ),
                CJISRequirement(
                    id="5.6.3.2.2",
                    section="5.6.3.2",
                    title="Administrative Procedures",
                    requirement_text="Agencies shall establish administrative procedures for initial authenticator distribution, for lost/compromised/damaged authenticators, and for revoking authenticators.",
                    keywords=["administrative", "procedures", "distribution", "lost", "compromised", "damaged", "revoking"]
                ),
                CJISRequirement(
                    id="5.6.3.2.3",
                    section="5.6.3.2",
                    title="Change Default Authenticators",
                    requirement_text="Agencies shall change default authenticators upon information system installation.",
                    keywords=["change", "default", "authenticators", "installation", "system"]
                ),
                CJISRequirement(
                    id="5.6.3.2.4",
                    section="5.6.3.2",
                    title="Periodic Authenticator Changes",
                    requirement_text="Agencies shall change/refresh authenticators periodically.",
                    keywords=["change", "refresh", "authenticators", "periodically", "regular"]
                ),
                CJISRequirement(
                    id="5.6.3.2.5",
                    section="5.6.3.2",
                    title="User Safeguarding Responsibilities",
                    requirement_text="Users shall take reasonable measures to safeguard authenticators including maintaining possession of their individual authenticators, not loaning or sharing authenticators with others, and immediately reporting lost or compromised authenticators.",
                    keywords=["safeguard", "maintain possession", "not sharing", "not loaning", "report", "lost", "compromised"]
                )
            ],

            "media_protection": [
                CJISRequirement(
                    id="5.10.1.1",
                    section="5.10.1",
                    title="Media Access Control",
                    requirement_text="The information system shall restrict access to digital and non-digital media to authorized individuals.",
                    keywords=["restrict access", "media", "authorized", "individuals"]
                ),

                CJISRequirement(
                    id="5.10.2.1",
                    section="5.10.2",
                    title="Media Sanitization",
                    requirement_text="The organization shall sanitize information system media, both digital and non-digital, prior to disposal, release out of organizational control, or release for reuse.",
                    keywords=["sanitize", "media", "disposal", "release", "reuse", "NIST SP 800-88"]
                )
            ],
            # --- NEW SECTION ADDED ---
            "access_control": [
                CJISRequirement(
                    id="5.2.1",
                    section="5.2",
                    title="Least Privilege Access",
                    requirement_text="Agencies shall enforce the principle of least privilege, allowing only authorized accesses for users (or processes acting on behalf of users) which are necessary to accomplish assigned tasks.",
                    keywords=["least privilege", "authorized access", "need-to-know", "need-to-share", "role-based"]
                ),
                CJISRequirement(
                    id="5.2.2",
                    section="5.2",
                    title="Account Management - Disabling Inactive Accounts",
                    requirement_text="The information system shall automatically disable inactive accounts after a period of 90 days.",
                    keywords=["disable", "inactive", "accounts", "90 days", "ninety"]
                ),
                CJISRequirement(
                    id="5.2.3",
                    section="5.2",
                    title="Account Management - Concurrent Sessions",
                    requirement_text="The information system shall prevent multiple concurrent active sessions for one user identification unless explicitly authorized by the agency.",
                    keywords=["concurrent", "sessions", "multiple", "user identification", "prevent"]
                ),
                CJISRequirement(
                    id="5.2.4",
                    section="5.2",
                    title="Object-Level Access Control",
                    requirement_text="Access control mechanisms shall be restricted by object (e.g., data set, volumes, files, records) including the ability to read, write, or delete the objects.",
                    keywords=["restrict", "object", "files", "records", "read", "write", "delete"]
                )
            ],

            "audit_and_accountability": [
                CJISRequirement(
                    id="5.4.1",
                    section="5.4",
                    title="Audit Log Generation",
                    requirement_text="The information system shall generate audit records containing information that establishes what type of event occurred, when the event occurred, where the event occurred, the source of the event, the outcome of the event, and the identity of any user/subject associated with the event.",
                    keywords=["audit records", "generate", "event", "when", "where", "source", "outcome", "identity", "user"]
                ),
                CJISRequirement(
                    id="5.4.2",
                    section="5.4",
                    title="Audit Log Review",
                    requirement_text="Agencies shall review/analyze information system audit records at least weekly for indications of inappropriate or unusual activity.",
                    keywords=["review", "analyze", "audit records", "weekly", "inappropriate", "unusual activity"]
                ),
                CJISRequirement(
                    id="5.4.3",
                    section="5.4",
                    title="Audit Log Retention",
                    requirement_text="Agencies shall retain audit logs for at least one year (365 days).",
                    keywords=["retain", "audit logs", "one year", "365 days"]
                )
            ],

            # --- PASTE THIS NEW SECTION IN ---
            "physical_protection": [
                CJISRequirement(
                    id="5.9.1",
                    section="5.9",
                    title="Physical Access Control",
                    requirement_text="The agency shall limit physical access to information systems, equipment, and the respective operating environments to authorized individuals.",
                    keywords=["limit", "physical access", "systems", "equipment", "authorized individuals"]
                ),
                CJISRequirement(
                    id="5.9.2",
                    section="5.9",
                    title="Visitor Control",
                    requirement_text="The agency shall escort visitors and monitor visitor activity in all physically secure locations.",
                    keywords=["escort", "visitors", "monitor", "visitor activity", "secure locations"]
                ),
                CJISRequirement(
                    id="5.9.3",
                    section="5.9",
                    title="Visitor Access Records",
                    requirement_text="The agency shall maintain visitor access records to the facility for one (1) year and review them quarterly.",
                    keywords=["visitor access records", "maintain", "one year", "365 days", "review", "quarterly"]
                ),
                CJISRequirement(
                    id="5.9.4",
                    section="5.9",
                    title="Monitoring Physical Access",
                    requirement_text="The agency shall monitor physical access to the facility where the system resides using physical intrusion alarms and surveillance equipment.",
                    keywords=["monitor", "physical access", "intrusion alarms", "surveillance", "cameras"]
                )
            ]
        }
