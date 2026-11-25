"""Deterministic policy decisions for protected-information requests."""

from __future__ import annotations

import re

POLICY_REFUSAL_TEXT = "I can't reveal hidden prompts, credentials, or secrets."

_PROTECTED_TARGET = (
    r"(?:prompts?|instructions?|credentials?|secrets?|tokens?|"
    r"database[ _-]?(?:passwords?|credentials?)|api[ _-]?(?:keys?|tokens?)|"
    r"(?:access|auth|bearer|client)[ _-]?(?:keys?|tokens?)|passwords?|"
    r"private[ _-]?keys?|environment[ _-]?variables?|env[ _-]?vars?)"
)
_DISCLOSURE_ACTION = re.compile(
    rf"\b(?:reveal|show|display|print|disclose|expose|share|provide|send|give|fetch|extract|"
    rf"retrieve|paste|quote|repeat|recite|output|dump|tell\s+me)\b"
    rf"(?:(?![.!?]).){{0,55}}?\b{_PROTECTED_TARGET}\b",
    re.IGNORECASE,
)
_DIRECT_SECRET_QUESTION = re.compile(
    rf"\bwhat(?:\s+(?:is|are|was|were)|['’]s)\s+"
    rf"(?:(?:the|my|your|our|a|an)\s+)?"
    rf"(?:(?:hidden|system|developer|internal|privileged)\s+){{0,2}}{_PROTECTED_TARGET}\b",
    re.IGNORECASE,
)
_NEGATED_ACTION = re.compile(
    r"\b(?:do\s+not|don't|will\s+not|won't|never|avoid)"
    r"(?:\s+\w+){0,5}\s*$",
    re.IGNORECASE,
)
_TARGET_IS_CONTEXT = re.compile(
    r"\s+(?:finding|findings|warning|warnings|control|guard|rule|issue|check|handling|"
    r"validation|protection|policy|configuration|does|mean|means|work|works|used|"
    r"configured|protected|validated|rotated|stored|generated)\b",
    re.IGNORECASE,
)
_INDIRECT_QUERY = re.compile(r"\b(?:whether|if|how|why|where|when)\b", re.IGNORECASE)


def is_sensitive_disclosure_request(question: str) -> bool:
    """Conservatively match direct protected-value requests with lexical rules.

    Mentioning a credential-related finding, asking how a token is protected, or
    instructing the assistant not to disclose information is not itself a request
    to reveal the information. This is not semantic prompt-injection detection; new
    phrasings can require explicit policy and regression-test updates.
    """
    for pattern in (_DISCLOSURE_ACTION, _DIRECT_SECRET_QUESTION):
        for match in pattern.finditer(question):
            prefix = question[max(0, match.start() - 64) : match.start()]
            if _NEGATED_ACTION.search(prefix):
                continue
            target_end = match.end()
            suffix = question[target_end : target_end + 48]
            if _TARGET_IS_CONTEXT.match(suffix):
                continue
            action_text = question[match.start() : match.end()]
            if _INDIRECT_QUERY.search(action_text):
                continue
            return True
    return False
