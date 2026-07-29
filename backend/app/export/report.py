from typing import Dict, List

from app.corpus.models import ComplianceCheck, ComplianceStatus


def generate_audit_checklist(compliance_checks: List[ComplianceCheck]) -> Dict:
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


def export_final_report(compliance_checks: List[ComplianceCheck]) -> Dict:
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
        "recommendations": _generate_prioritized_recommendations(confirmed_checks)
    }


def _generate_prioritized_recommendations(checks: List[ComplianceCheck]) -> List[Dict]:
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
