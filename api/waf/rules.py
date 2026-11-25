"""
WAF Security Rules

Defines pattern-based rules for detecting common web attack vectors
including SQL injection, XSS, and malicious payloads.
"""

import re
from typing import List, Tuple, Pattern
from dataclasses import dataclass, field
from enum import Enum


class ThreatLevel(Enum):
    """Classification of threat severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SecurityRule:
    """Represents a single security rule with pattern and metadata."""
    id: str
    name: str
    pattern: Pattern
    threat_level: ThreatLevel
    description: str
    enabled: bool = True


@dataclass
class SecurityRules:
    """
    Collection of security rules for WAF inspection.
    
    Implements detection patterns for:
    - SQL Injection attacks
    - Cross-Site Scripting (XSS)
    - Path traversal attempts
    - Command injection
    - Header manipulation
    - Server-side request forgery (SSRF)
    - JNDI lookup injection (Log4Shell style)
    - XML external entities (XXE)
    """
    
    _sql_injection_patterns: List[SecurityRule] = field(default_factory=list)
    _xss_patterns: List[SecurityRule] = field(default_factory=list)
    _path_traversal_patterns: List[SecurityRule] = field(default_factory=list)
    _command_injection_patterns: List[SecurityRule] = field(default_factory=list)
    _ssrf_patterns: List[SecurityRule] = field(default_factory=list)
    _jndi_patterns: List[SecurityRule] = field(default_factory=list)
    _xxe_patterns: List[SecurityRule] = field(default_factory=list)
    
    def __post_init__(self):
        """Initialize all security rule patterns."""
        self._initialize_sql_injection_rules()
        self._initialize_xss_rules()
        self._initialize_path_traversal_rules()
        self._initialize_command_injection_rules()
        self._initialize_ssrf_rules()
        self._initialize_jndi_rules()
        self._initialize_xxe_rules()
    
    def _initialize_sql_injection_rules(self) -> None:
        """Define SQL injection detection patterns."""
        patterns = [
            (r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\b.*\b(FROM|INTO|TABLE|SET)\b)", 
             "SQL keyword combination"),
            (r"(\bOR\b\s+\d+\s*=\s*\d+)", "OR-based SQL injection"),
            (r"(\bAND\b\s+\d+\s*=\s*\d+)", "AND-based SQL injection"),
            (r"(--|\#|\/\*)", "SQL comment injection"),
            (r"(\bUNION\b\s+\bSELECT\b)", "UNION SELECT injection"),
            (r"(\bEXEC\b|\bEXECUTE\b)\s*\(", "SQL EXEC injection"),
            (r"(\bDECLARE\b\s+@)", "SQL variable declaration"),
            (r"(\bCAST\b\s*\(.*\bAS\b)", "SQL CAST injection"),
            (r"(\bCONVERT\b\s*\()", "SQL CONVERT injection"),
            (r"(\bWAITFOR\b\s+\bDELAY\b)", "SQL time-based injection"),
            (r"(\'|\")(\s*)(OR|AND)(\s*)(\'|\"|\d)", "Quote-based injection"),
            (r"(\bINFORMATION_SCHEMA\b)", "Schema enumeration"),
            (r"(\bSYSOBJECTS\b|\bSYSTABLES\b)", "System table access"),
        ]
        
        for i, (pattern, desc) in enumerate(patterns):
            self._sql_injection_patterns.append(SecurityRule(
                id=f"SQLI-{i+1:03d}",
                name=f"SQL Injection: {desc}",
                pattern=re.compile(pattern, re.IGNORECASE),
                threat_level=ThreatLevel.CRITICAL,
                description=f"Detects {desc}"
            ))
    
    def _initialize_xss_rules(self) -> None:
        """Define XSS detection patterns."""
        patterns = [
            (r"<script[^>]*>", "Script tag"),
            (r"javascript\s*:", "JavaScript protocol"),
            (r"on\w+\s*=", "Event handler attribute"),
            (r"<iframe[^>]*>", "Iframe injection"),
            (r"<object[^>]*>", "Object tag injection"),
            (r"<embed[^>]*>", "Embed tag injection"),
            (r"<svg[^>]*onload", "SVG onload injection"),
            (r"<img[^>]*onerror", "Image onerror injection"),
            (r"<body[^>]*onload", "Body onload injection"),
            (r"expression\s*\(", "CSS expression injection"),
            (r"vbscript\s*:", "VBScript protocol"),
            (r"data\s*:\s*text\/html", "Data URL injection"),
            (r"<link[^>]*href\s*=\s*['\"]?javascript", "Link javascript injection"),
        ]
        
        for i, (pattern, desc) in enumerate(patterns):
            self._xss_patterns.append(SecurityRule(
                id=f"XSS-{i+1:03d}",
                name=f"XSS: {desc}",
                pattern=re.compile(pattern, re.IGNORECASE),
                threat_level=ThreatLevel.HIGH,
                description=f"Detects {desc}"
            ))
    
    def _initialize_path_traversal_rules(self) -> None:
        """Define path traversal detection patterns."""
        patterns = [
            (r"\.\.\/", "Directory traversal with forward slash"),
            (r"\.\.\\", "Directory traversal with backslash"),
            (r"%2e%2e%2f", "URL encoded traversal"),
            (r"%2e%2e\/", "Mixed encoded traversal"),
            (r"\.\.%2f", "Partial encoded traversal"),
            (r"\/etc\/passwd", "Unix passwd file access"),
            (r"\/etc\/shadow", "Unix shadow file access"),
            (r"c:\\windows", "Windows system path"),
            (r"%00", "Null byte injection"),
        ]
        
        for i, (pattern, desc) in enumerate(patterns):
            self._path_traversal_patterns.append(SecurityRule(
                id=f"PATH-{i+1:03d}",
                name=f"Path Traversal: {desc}",
                pattern=re.compile(pattern, re.IGNORECASE),
                threat_level=ThreatLevel.HIGH,
                description=f"Detects {desc}"
            ))
    
    def _initialize_command_injection_rules(self) -> None:
        """Define command injection detection patterns."""
        patterns = [
            (r";\s*(ls|cat|rm|wget|curl)\b", "Unix command chaining"),
            (r"\|\s*(ls|cat|rm|wget|curl)\b", "Unix pipe injection"),
            (r"`[^`]+`", "Backtick command execution"),
            (r"\$\([^)]+\)", "Subshell execution"),
            (r"&&\s*(ls|cat|rm|wget|curl)\b", "AND command chaining"),
            (r"\|\|\s*(ls|cat|rm|wget|curl)\b", "OR command chaining"),
            (r">\s*\/", "Output redirection to root"),
            (r"<\s*\/", "Input redirection from root"),
        ]
        
        for i, (pattern, desc) in enumerate(patterns):
            self._command_injection_patterns.append(SecurityRule(
                id=f"CMDI-{i+1:03d}",
                name=f"Command Injection: {desc}",
                pattern=re.compile(pattern, re.IGNORECASE),
                threat_level=ThreatLevel.CRITICAL,
                description=f"Detects {desc}"
            ))
    
    def _initialize_ssrf_rules(self) -> None:
        """
        Define SSRF signatures (requests aimed at internal hosts).

        These match request strings only. They do not replace validating the
        destination inside the code that makes the outbound request.
        """
        host = r"https?://(?:[^/\s@?#]{0,100}@)?"
        patterns = [
            (host + r"(?:localhost|[a-z0-9-]+\.localhost|metadata\.google\.internal|metadata\.goog)\.?(?![\w.-])",
             "Internal hostname"),
            (host + r"(?:127(?:\.\d{1,3}){1,3}|0(?:\.0){0,3}|0x[0-9a-f]+(?:\.[0-9a-fx]+){0,3}|\d{8,10}|0\d+(?:\.\d+){0,3})(?![\w.-])",
             "Loopback address (dotted, short, decimal, hex or octal form)"),
            (host + r"(?:169\.254(?:\.\d{1,3}){2}|10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}"
                    r"|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}"
                    r"|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])(?:\.\d{1,3}){2})(?![\w.-])",
             "Link-local, private or CGNAT address in URL"),
            (host + r"\[(?:(?:0{0,4}:){1,7}0{0,3}1?|::ffff:[0-9a-f.:]+|f[cd][0-9a-f]{0,2}:[0-9a-f:]*"
                    r"|fe[89ab][0-9a-f]:[0-9a-f:]*)\]",
             "IPv6 loopback, mapped, unique-local or link-local address"),
            (r"\b(?:file|gopher|dict)://", "Dangerous URL scheme"),
        ]
        for i, (pattern, desc) in enumerate(patterns):
            self._ssrf_patterns.append(SecurityRule(
                id=f"SSRF-{i+1:03d}",
                name=f"SSRF: {desc}",
                pattern=re.compile(pattern, re.IGNORECASE),
                threat_level=ThreatLevel.HIGH,
                description=f"Detects {desc}"
            ))

    def _initialize_jndi_rules(self) -> None:
        """Define JNDI lookup injection patterns (Log4Shell style)."""
        patterns = [
            # Bounded repetition keeps this linear on long runs of "${".
            (r"\$\{(?:[a-z:\-]|\$\{[^}]{0,40}\}){0,40}?ndi:", "JNDI lookup, including obfuscated forms"),
        ]
        for i, (pattern, desc) in enumerate(patterns):
            self._jndi_patterns.append(SecurityRule(
                id=f"JNDI-{i+1:03d}",
                name=f"JNDI Injection: {desc}",
                pattern=re.compile(pattern, re.IGNORECASE),
                threat_level=ThreatLevel.CRITICAL,
                description=f"Detects {desc}"
            ))

    def _initialize_xxe_rules(self) -> None:
        """Define XML external entity (XXE) detection patterns."""
        patterns = [
            (r"<!DOCTYPE[^>]*\[", "DOCTYPE with internal subset"),
            (r"<!ENTITY[^>]*\b(SYSTEM|PUBLIC)\b", "External entity declaration"),
        ]
        for i, (pattern, desc) in enumerate(patterns):
            self._xxe_patterns.append(SecurityRule(
                id=f"XXE-{i+1:03d}",
                name=f"XXE: {desc}",
                pattern=re.compile(pattern, re.IGNORECASE),
                threat_level=ThreatLevel.HIGH,
                description=f"Detects {desc}"
            ))

    def get_all_rules(self) -> List[SecurityRule]:
        """Return all enabled security rules."""
        all_rules = (
            self._sql_injection_patterns +
            self._xss_patterns +
            self._path_traversal_patterns +
            self._command_injection_patterns +
            self._ssrf_patterns +
            self._jndi_patterns +
            self._xxe_patterns
        )
        return [rule for rule in all_rules if rule.enabled]
    
    def get_rules_by_threat_level(self, level: ThreatLevel) -> List[SecurityRule]:
        """Return rules filtered by threat level."""
        return [rule for rule in self.get_all_rules() if rule.threat_level == level]
    
    def check_content(self, content: str) -> List[Tuple[SecurityRule, str]]:
        """
        Check content against all security rules.
        
        Args:
            content: The string content to analyze
            
        Returns:
            List of tuples containing matched rules and the matching substring
        """
        violations = []
        for rule in self.get_all_rules():
            match = rule.pattern.search(content)
            if match:
                violations.append((rule, match.group()))
        return violations
