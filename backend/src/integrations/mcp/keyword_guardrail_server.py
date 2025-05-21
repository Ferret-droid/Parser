import logging
import re
import json
from datetime import datetime
from typing import Dict, List, Any, Tuple
from mcp.server.fastmcp import FastMCP, Context

# Configure logging for keyword guardrails
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('keyword_guardrails.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('keyword_guardrails')

# Create MCP server
mcp = FastMCP("Keyword Guardrail Server")

# Keyword dictionaries organized by category
KEYWORD_CATEGORIES = {
    "identifier": {
        "keywords": [
            "classified", "confidential", "secret", "top secret", "restricted",
            "internal only", "proprietary", "privileged", "sensitive",
            "ssn", "social security", "tax id", "employee id", "patient id",
            "credit card", "bank account", "routing number", "passport",
            "driver license", "medical record", "financial record"
        ],
        "patterns": [
            r'\b(ssn|social.security)\s*[:\-]?\s*\d{3}[-\s]?\d{2}[-\s]?\d{4}\b',
            r'\b(cc|credit.card)\s*[:\-]?\s*\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
            r'\b(account|acct)\s*[:\-]?\s*\d{8,12}\b',
            r'\b(employee|emp|patient)\s*id\s*[:\-]?\s*[a-z0-9]{5,15}\b'
        ],
        "threshold": 1
    },
    "high_confidence": {
        "keywords": [
            "breach", "leak", "unauthorized", "violation", "non-compliance",
            "expose", "disclosure", "compromise", "vulnerability", "incident",
            "privacy violation", "data loss", "security incident", "hack",
            "malware", "ransomware", "phishing", "fraud", "identity theft",
            "laundering", "embezzlement", "corruption", "bribery"
        ],
        "patterns": [
            r'\b(password|pwd)\s*[:\-]?\s*[a-z0-9!@#$%^&*]{6,}\b',
            r'\b(api.key|token)\s*[:\-]?\s*[a-z0-9]{20,}\b',
            r'\b(unauthorized\s+access|security\s+breach)\b',
            r'\b(data\s+exfiltration|information\s+theft)\b'
        ],
        "threshold": 1
    },
    "general": {
        "keywords": [
            "personal", "private", "financial", "medical", "health",
            "insurance", "legal", "contract", "agreement", "settlement",
            "investment", "salary", "compensation", "bonus", "performance",
            "disciplinary", "termination", "resignation", "merger",
            "acquisition", "strategy", "competitive", "intellectual property",
            "patent", "trademark", "copyright", "trade secret", "algorithm",
            "source code", "database", "backup", "archive", "log file"
        ],
        "patterns": [
            r'\b(personal\s+information|private\s+data)\b',
            r'\b(financial\s+statement|medical\s+record)\b',
            r'\b(trade\s+secret|intellectual\s+property)\b',
            r'\b(source\s+code|database\s+schema)\b'
        ],
        "threshold": 2
    }
}

# Permission matrix for different sensitivity levels
PERMISSION_MATRIX = {
    "admin": ["all"],
    "security_officer": ["all"],
    "compliance_manager": ["sensitive", "confidential"],
    "manager": ["confidential"],
    "senior_employee": ["internal"],
    "employee": ["general"],
    "contractor": ["general"],
    "guest": []
}

# Audit log storage (use database in production)
keyword_audit_log = []

def find_keyword_matches(text: str, category: str) -> Tuple[List[str], List[str]]:
    """
    Find keyword and pattern matches in text for a specific category.
    Returns tuple of (keyword_matches, pattern_matches)
    """
    text_lower = text.lower()
    category_data = KEYWORD_CATEGORIES[category]
    
    # Find keyword matches
    keyword_matches = []
    for keyword in category_data["keywords"]:
        if keyword.lower() in text_lower:
            keyword_matches.append(keyword)
    
    # Find pattern matches
    pattern_matches = []
    for pattern in category_data.get("patterns", []):
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            pattern_matches.extend([str(match) if isinstance(match, tuple) else match for match in matches])
    
    return keyword_matches, pattern_matches

@mcp.tool()
def analyze_keyword_sensitivity(text: str, user_id: str, user_roles: List[str] = None, context: str = None) -> Dict[str, Any]:
    """
    Analyzes text for keyword combinations that indicate sensitive material.
    Checks if user has permission to access material with detected sensitivity.
    Logs all interactions for audit purposes.
    
    Triggering Rules:
    - 1+ Identifier keywords
    - 1+ High Confidence keywords  
    - 2+ General keywords
    """
    if user_roles is None:
        user_roles = ["employee"]
    
    timestamp = datetime.now().isoformat()
    analysis_id = f"analysis_{len(keyword_audit_log) + 1}_{int(datetime.now().timestamp())}"
    
    # Analyze keyword matches by category
    category_results = {}
    total_matches = 0
    
    for category in KEYWORD_CATEGORIES.keys():
        keyword_matches, pattern_matches = find_keyword_matches(text, category)
        all_matches = keyword_matches + pattern_matches
        threshold = KEYWORD_CATEGORIES[category]["threshold"]
        
        category_results[category] = {
            "keyword_matches": keyword_matches,
            "pattern_matches": pattern_matches,
            "total_matches": len(all_matches),
            "threshold": threshold,
            "threshold_met": len(all_matches) >= threshold,
            "matches": all_matches
        }
        total_matches += len(all_matches)
    
    # Determine if combination rule is triggered
    rule_triggered = (
        category_results["identifier"]["threshold_met"] and
        category_results["high_confidence"]["threshold_met"] and
        category_results["general"]["threshold_met"]
    )
    
    # Determine sensitivity level based on matches
    if rule_triggered:
        sensitivity_level = "sensitive"
    elif category_results["identifier"]["threshold_met"] or category_results["high_confidence"]["threshold_met"]:
        sensitivity_level = "confidential"
    elif category_results["general"]["total_matches"] > 0:
        sensitivity_level = "internal"
    else:
        sensitivity_level = "general"
    
    # Check user permissions
    access_granted = False
    authorized_roles = []
    
    for role in user_roles:
        if role in PERMISSION_MATRIX:
            permissions = PERMISSION_MATRIX[role]
            if "all" in permissions or sensitivity_level in permissions:
                access_granted = True
                authorized_roles.append(role)
    
    # Create comprehensive result
    result = {
        "analysis_id": analysis_id,
        "timestamp": timestamp,
        "user_id": user_id,
        "user_roles": user_roles,
        "text_length": len(text),
        "context": context,
        "category_analysis": category_results,
        "total_keyword_matches": total_matches,
        "combination_rule_triggered": rule_triggered,
        "sensitivity_level": sensitivity_level,
        "access_granted": access_granted,
        "authorized_roles": authorized_roles,
        "action_required": "BLOCK" if rule_triggered and not access_granted else "ALLOW",
        "recommendations": []
    }
    
    # Add specific recommendations
    if rule_triggered and not access_granted:
        result["recommendations"] = [
            "Block access to material",
            "Alert security team",
            "Require higher authorization",
            "Document access attempt"
        ]
    elif rule_triggered and access_granted:
        result["recommendations"] = [
            "Allow access with enhanced logging",
            "Monitor user activity",
            "Alert compliance team"
        ]
    elif not rule_triggered and total_matches > 0:
        result["recommendations"] = [
            "Standard access procedures",
            "Log interaction"
        ]
    
    # Log to audit trail
    audit_entry = {
        "analysis_id": analysis_id,
        "timestamp": timestamp,
        "user_id": user_id,
        "user_roles": user_roles,
        "context": context,
        "sensitivity_level": sensitivity_level,
        "rule_triggered": rule_triggered,
        "access_granted": access_granted,
        "action_taken": result["action_required"],
        "identifier_matches": category_results["identifier"]["total_matches"],
        "high_confidence_matches": category_results["high_confidence"]["total_matches"],
        "general_matches": category_results["general"]["total_matches"],
        "matched_keywords": {
            "identifier": category_results["identifier"]["matches"],
            "high_confidence": category_results["high_confidence"]["matches"],
            "general": category_results["general"]["matches"]
        }
    }
    
    keyword_audit_log.append(audit_entry)
    
    # Log with appropriate level
    if rule_triggered and not access_granted:
        logger.critical(f"BLOCKED ACCESS: {user_id} attempted to access sensitive material - Rule triggered, insufficient permissions")
    elif rule_triggered and access_granted:
        logger.warning(f"SENSITIVE ACCESS: {user_id} accessed sensitive material - Rule triggered, authorized")
    else:
        logger.info(f"CONTENT ANALYSIS: {user_id} - Sensitivity: {sensitivity_level}, Matches: {total_matches}")
    
    return result

@mcp.tool()
def check_keyword_permissions(user_id: str, sensitivity_level: str, user_roles: List[str] = None) -> Dict[str, Any]:
    """
    Standalone tool to check if a user has permission to access material 
    at a specific sensitivity level.
    """
    if user_roles is None:
        user_roles = ["employee"]
    
    access_granted = False
    authorized_roles = []
    missing_roles = []
    
    # Check each role
    for role in user_roles:
        if role in PERMISSION_MATRIX:
            permissions = PERMISSION_MATRIX[role]
            if "all" in permissions or sensitivity_level in permissions:
                access_granted = True
                authorized_roles.append(role)
    
    # Find what roles would be needed
    for role, permissions in PERMISSION_MATRIX.items():
        if "all" in permissions or sensitivity_level in permissions:
            if role not in user_roles:
                missing_roles.append(role)
    
    result = {
        "user_id": user_id,
        "user_roles": user_roles,
        "sensitivity_level": sensitivity_level,
        "access_granted": access_granted,
        "authorized_roles": authorized_roles,
        "missing_roles": missing_roles[:3],  # Show top 3 roles that would grant access
        "permission_matrix": PERMISSION_MATRIX,
        "timestamp": datetime.now().isoformat()
    }
    
    return result

@mcp.tool()
def simulate_keyword_scenario(scenario_name: str) -> Dict[str, Any]:
    """
    Simulates different keyword matching scenarios for testing.
    """
    scenarios = {
        "low_risk": {
            "text": "This document contains general business information about our quarterly performance and strategic planning initiatives.",
            "user_id": "john.doe",
            "user_roles": ["employee"],
            "context": "quarterly_report_access"
        },
        "medium_risk": {
            "text": "This confidential document contains employee personal information and performance reviews for internal management use.",
            "user_id": "manager.smith",
            "user_roles": ["manager"],
            "context": "hr_document_access"
        },
        "high_risk_authorized": {
            "text": "CLASSIFIED: This document contains sensitive financial records with SSN 123-45-6789, shows a security breach incident involving unauthorized access to our database containing personal medical records.",
            "user_id": "security.admin",
            "user_roles": ["admin", "security_officer"],
            "context": "incident_investigation"
        },
        "high_risk_blocked": {
            "text": "CLASSIFIED: This document contains sensitive financial records with SSN 123-45-6789, shows a security breach incident involving unauthorized access to our database containing personal medical records.",
            "user_id": "contractor.temp",
            "user_roles": ["contractor"],
            "context": "unauthorized_access_attempt"
        },
        "edge_case": {
            "text": "Password: admin123, this confidential breach report details unauthorized access to classified patient medical records and SSN data.",
            "user_id": "intern.new",
            "user_roles": ["intern"],
            "context": "training_material_access"
        }
    }
    
    if scenario_name not in scenarios:
        return {"error": f"Unknown scenario. Available: {list(scenarios.keys())}"}
    
    scenario = scenarios[scenario_name]
    result = analyze_keyword_sensitivity(
        text=scenario["text"],
        user_id=scenario["user_id"],
        user_roles=scenario["user_roles"],
        context=scenario["context"]
    )
    
    # Add scenario context
    result["scenario_name"] = scenario_name
    result["scenario_description"] = scenario
    
    return result

@mcp.resource("keywords://categories")
def get_keyword_categories() -> str:
    """
    Returns the complete keyword categories configuration.
    """
    return json.dumps(KEYWORD_CATEGORIES, indent=2)

@mcp.resource("keywords://permissions")
def get_permission_matrix() -> str:
    """
    Returns the permission matrix configuration.
    """
    return json.dumps(PERMISSION_MATRIX, indent=2)

@mcp.resource("audit://keyword-logs")
def get_keyword_audit_logs() -> str:
    """
    Returns recent keyword analysis audit logs.
    """
    # Return last 20 logs
    recent_logs = keyword_audit_log[-20:] if keyword_audit_log else []
    return json.dumps(recent_logs, indent=2)

@mcp.resource("audit://blocked-attempts")
def get_blocked_attempts() -> str:
    """
    Returns audit logs of blocked access attempts.
    """
    blocked_attempts = [
        log for log in keyword_audit_log 
        if not log["access_granted"] and log["rule_triggered"]
    ]
    return json.dumps(blocked_attempts[-10:], indent=2)

@mcp.resource("audit://sensitive-access")
def get_sensitive_access_logs() -> str:
    """
    Returns audit logs of successful access to sensitive material.
    """
    sensitive_access = [
        log for log in keyword_audit_log 
        if log["access_granted"] and log["rule_triggered"]
    ]
    return json.dumps(sensitive_access[-10:], indent=2)

@mcp.tool()
def keyword_statistics() -> Dict[str, Any]:
    """
    Provides statistics about keyword analysis and access patterns.
    """
    if not keyword_audit_log:
        return {"message": "No audit data available yet"}
    
    total_analyses = len(keyword_audit_log)
    rule_triggered = len([log for log in keyword_audit_log if log["rule_triggered"]])
    blocked_attempts = len([log for log in keyword_audit_log if not log["access_granted"] and log["rule_triggered"]])
    sensitive_access = len([log for log in keyword_audit_log if log["access_granted"] and log["rule_triggered"]])
    
    # Sensitivity level distribution
    sensitivity_counts = {}
    for log in keyword_audit_log:
        level = log["sensitivity_level"]
        sensitivity_counts[level] = sensitivity_counts.get(level, 0) + 1
    
    # Most active users
    user_counts = {}
    for log in keyword_audit_log:
        user = log["user_id"]
        user_counts[user] = user_counts.get(user, 0) + 1
    
    # Most triggered keywords by category
    keyword_stats = {
        "identifier": {},
        "high_confidence": {},
        "general": {}
    }
    
    for log in keyword_audit_log:
        for category, matches in log["matched_keywords"].items():
            for keyword in matches:
                if keyword in keyword_stats[category]:
                    keyword_stats[category][keyword] += 1
                else:
                    keyword_stats[category][keyword] = 1
    
    return {
        "summary": {
            "total_analyses": total_analyses,
            "rule_triggered": rule_triggered,
            "blocked_attempts": blocked_attempts,
            "sensitive_access_granted": sensitive_access,
            "rule_trigger_rate": f"{(rule_triggered/total_analyses*100):.1f}%" if total_analyses > 0 else "0%",
            "block_rate": f"{(blocked_attempts/total_analyses*100):.1f}%" if total_analyses > 0 else "0%"
        },
        "sensitivity_distribution": sensitivity_counts,
        "top_users": dict(sorted(user_counts.items(), key=lambda x: x[1], reverse=True)[:5]),
        "top_triggered_keywords": {
            category: dict(sorted(keywords.items(), key=lambda x: x[1], reverse=True)[:5])
            for category, keywords in keyword_stats.items()
        },
        "timestamp": datetime.now().isoformat()
    }

if __name__ == "__main__":
    mcp.run()