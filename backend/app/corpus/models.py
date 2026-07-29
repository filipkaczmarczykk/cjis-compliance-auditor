from dataclasses import dataclass
from typing import List, Dict, Optional
from enum import Enum
#import openai  # For LLM integration when ready

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


        
    
    def check_section(self, section_name: str, agency_policy_text: str) -> List[ComplianceCheck]:
        """
        Check all requirements in a CJIS section against agency policy.
        Returns list of compliance checks that require auditor review.
        """
        if section_name not in self.cjis_requirements:
            raise ValueError(f"Unknown CJIS section: {section_name}")
            
        requirements = self.cjis_requirements[section_name]
        compliance_checks = []
        
        for requirement in requirements:
            check = self._analyze_requirement(requirement, agency_policy_text)
            compliance_checks.append(check)
            
        return compliance_checks
    
    def _analyze_requirement(self, requirement: CJISRequirement, agency_policy: str) -> ComplianceCheck:
        """
        Analyze single requirement against agency policy.
        Uses LLM for semantic analysis when available, falls back to keyword matching.
        """
        if self.llm_client:
            return self._llm_analysis(requirement, agency_policy)
        else:
            return self._keyword_analysis(requirement, agency_policy)
    
    def _llm_analysis(self, requirement: CJISRequirement, agency_policy: str) -> ComplianceCheck:
        """LLM-powered semantic analysis (implement when ready)"""
        prompt = f"""
        CJIS Requirement: {requirement.requirement_text}
        
        Agency Policy: {agency_policy}
        
        Analyze if the agency policy meets this specific CJIS requirement.
        
        Respond with JSON:
        {{
            "compliant": true/false,
            "confidence": 0.0-1.0,
            "evidence": "exact quote from agency policy that addresses this requirement",
            "issues": ["specific gaps or problems"],
            "suggestions": ["specific changes needed"]
        }}
        """
        
        # LLM call would go here
        # response = self.llm_client.chat.completions.create(...)
        
        # For now, fallback to keyword analysis
        return self._keyword_analysis(requirement, agency_policy)
    
    def _keyword_analysis(self, requirement: CJISRequirement, agency_policy: str) -> ComplianceCheck:
        """Keyword-based analysis as fallback"""
        policy_lower = agency_policy.lower()
        issues = []
        suggestions = []
        evidence_text = ""
        
        # Find relevant text sections
        relevant_sentences = []
        sentences = agency_policy.split('.')
        
        for sentence in sentences:
            if any(keyword.lower() in sentence.lower() for keyword in requirement.keywords):
                relevant_sentences.append(sentence.strip())
        
        evidence_text = '. '.join(relevant_sentences[:2])  # Top 2 relevant sentences
        
        # Determine compliance based on keyword coverage
        keyword_matches = sum(1 for keyword in requirement.keywords 
                            if keyword.lower() in policy_lower)
        coverage = keyword_matches / len(requirement.keywords)
        
        if coverage >= 0.7 and len(relevant_sentences) > 0:
            status = ComplianceStatus.COMPLIANT
            confidence = min(0.85, coverage)
        elif coverage >= 0.3:
            status = ComplianceStatus.NON_COMPLIANT
            confidence = 0.6
            issues.append(f"Partially addresses requirement but missing key elements")
            suggestions.append(f"Ensure policy explicitly addresses: {requirement.requirement_text}")
        else:
            status = ComplianceStatus.MISSING
            confidence = 0.3
            issues.append("No evidence found for this requirement")
            suggestions.append(f"Add policy section covering: {requirement.title}")
        
        return ComplianceCheck(
            requirement=requirement,
            status=status,
            confidence=confidence,
            evidence_text=evidence_text,
            issues=issues,
            suggestions=suggestions
        )
    
    def generate_audit_checklist(self, compliance_checks: List[ComplianceCheck]) -> Dict:
        """
        Generate structured checklist for auditor review.
        Groups findings by status and priority for efficient review.
        """
        checklist = {
            "summary": {
                "total_requirements": len(compliance_checks),
                "compliant": len([c for c in compliance_checks if c.status == ComplianceStatus.COMPLIANT]),
                "non_compliant": len([c for c in compliance_checks if c.status == ComplianceStatus.NON_COMPLIANT]),
                "missing": len([c for c in compliance_checks if c.status == ComplianceStatus.MISSING]),
                "pending_review": len([c for c in compliance_checks if not c.auditor_confirmed])
            },
            "critical_issues": [c for c in compliance_checks 
                             if c.requirement.critical and c.status != ComplianceStatus.COMPLIANT],
            "requires_confirmation": [c for c in compliance_checks if not c.auditor_confirmed],
            "by_section": {}
        }
        
        # Group by section for systematic review
        for check in compliance_checks:
            section = check.requirement.section
            if section not in checklist["by_section"]:
                checklist["by_section"][section] = []
            checklist["by_section"][section].append(check)
        
        return checklist
    
    def confirm_finding(self, check_id: str, auditor_confirmed: bool, notes: str = ""):
        """Allow auditor to confirm or override LLM findings"""
        # In full implementation, would update database/state
        pass
    
    def export_final_report(self, compliance_checks: List[ComplianceCheck]) -> Dict:
        """Generate final compliance report after auditor review"""
        confirmed_checks = [c for c in compliance_checks if c.auditor_confirmed]
        
        return {
            "agency": "Agency Name",
            "cjis_section": "Section Analyzed", 
            "audit_date": "2025-01-XX",
            "auditor": "Auditor Name",
            "total_requirements_checked": len(confirmed_checks),
            "compliance_summary": {
                "compliant": len([c for c in confirmed_checks if c.status == ComplianceStatus.COMPLIANT]),
                "non_compliant": len([c for c in confirmed_checks if c.status == ComplianceStatus.NON_COMPLIANT]),
                "missing": len([c for c in confirmed_checks if c.status == ComplianceStatus.MISSING])
            },
            "findings": confirmed_checks,
            "recommendations": self._generate_prioritized_recommendations(confirmed_checks)
        }
    
    def _generate_prioritized_recommendations(self, checks: List[ComplianceCheck]) -> List[Dict]:
        """Generate prioritized list of recommendations"""
        recommendations = []
        
        # Critical missing requirements first
        critical_missing = [c for c in checks 
                          if c.requirement.critical and c.status == ComplianceStatus.MISSING]
        
        for check in critical_missing:
            recommendations.append({
                "priority": "HIGH",
                "requirement": check.requirement.title,
                "issue": "Requirement completely missing from policy",
                "action": f"Add policy section addressing: {check.requirement.requirement_text}"
            })
        
        # Non-compliant requirements
        non_compliant = [c for c in checks if c.status == ComplianceStatus.NON_COMPLIANT]
        for check in non_compliant:
            recommendations.append({
                "priority": "MEDIUM" if check.requirement.critical else "LOW",
                "requirement": check.requirement.title,
                "issues": check.issues,
                "actions": check.suggestions
            })
        
        return recommendations

# Usage Example:
def main():
    checker = CJISComplianceChecker()
    
    # Sample agency policy text
    agency_policy = """
    METRO POLICE DEPARTMENT - AUTHENTICATOR MANAGEMENT POLICY
    
    Section 4.2: Access Control and Authentication
    All department personnel must use strong passwords containing at least 8 characters.
    Passwords must be changed every 90 days.
    New officers receive temporary login credentials during orientation.
    Default passwords must be changed upon first system login.
    Officers must immediately report lost ID badges to their supervisor.
    Personnel are prohibited from sharing login credentials.
    """
    
    # Run compliance check
    compliance_results = checker.check_section("authenticator_management", agency_policy)
    
    # Generate auditor checklist
    audit_checklist = checker.generate_audit_checklist(compliance_results)
    
    print("=== CJIS COMPLIANCE AUDIT CHECKLIST ===")
    print(f"Total Requirements: {audit_checklist['summary']['total_requirements']}")
    print(f"Compliant: {audit_checklist['summary']['compliant']}")
    print(f"Non-Compliant: {audit_checklist['summary']['non_compliant']}")
    print(f"Missing: {audit_checklist['summary']['missing']}")
    
    print("\n=== REQUIRES AUDITOR CONFIRMATION ===")
    for check in audit_checklist["requires_confirmation"]:
        print(f"\n{check.requirement.title}")
        print(f"Status: {check.status.value}")
        print(f"Evidence: {check.evidence_text}")
        print(f"Issues: {check.issues}")
        print("[ ] Auditor Confirmed")

if __name__ == "__main__":
    main()