"""Keyless, evidence-grounded hybrid retrieval for scan findings."""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any

from app.services.local_ai import embed_local_texts


@dataclass(frozen=True)
class _Document:
    document_id: str
    title: str
    content: str
    source_type: str
    citation: str
    endpoint: str | None = None
    source_url: str | None = None
    license: str | None = None


_SECURITY_KNOWLEDGE = (
    _Document(
        "owasp-api1",
        "Broken Object Level Authorization",
        "For every endpoint that accepts an object identifier, verify that the authenticated "
        "principal is authorized to access that specific object. Compare ownership or policy "
        "checks with object lookups; authentication alone does not prove authorization.",
        "security_knowledge",
        "OWASP API Security Top 10 2023: API1 Broken Object Level Authorization",
        source_url=(
            "https://api-security.owasp.org/editions/2023/en/"
            "0xa1-broken-object-level-authorization/"
        ),
        license="CC BY-SA 4.0",
    ),
    _Document(
        "owasp-api2",
        "Broken Authentication",
        "Authentication controls should protect operations that require an identity. Check "
        "effective OpenAPI security requirements against handler or middleware evidence. "
        "Static absence of a recognized check is a review signal, not proof of exploitability.",
        "security_knowledge",
        "OWASP API Security Top 10 2023: API2 Broken Authentication",
        source_url="https://api-security.owasp.org/editions/2023/en/0xa2-broken-authentication/",
        license="CC BY-SA 4.0",
    ),
    _Document(
        "owasp-api3",
        "Broken Object Property Level Authorization",
        "Restrict response fields and writable properties to what each caller is permitted "
        "to read or modify. Review mass assignment, sensitive response fields, and "
        "schema-to-code drift.",
        "security_knowledge",
        "OWASP API Security Top 10 2023: API3 Broken Object Property Level Authorization",
        source_url=(
            "https://api-security.owasp.org/editions/2023/en/"
            "0xa3-broken-object-property-level-authorization/"
        ),
        license="CC BY-SA 4.0",
    ),
    _Document(
        "owasp-api4",
        "Unrestricted Resource Consumption",
        "Apply bounded request sizes, pagination, rate limits, timeouts, and per-client quotas. "
        "A declared limit is useful only when it is enforced before expensive buffering or work.",
        "security_knowledge",
        "OWASP API Security Top 10 2023: API4 Unrestricted Resource Consumption",
        source_url=(
            "https://api-security.owasp.org/editions/2023/en/"
            "0xa4-unrestricted-resource-consumption/"
        ),
        license="CC BY-SA 4.0",
    ),
    _Document(
        "owasp-api5",
        "Broken Function Level Authorization",
        "Enforce authorization on privileged operations and verify role or policy checks at the "
        "server boundary. Hidden UI actions and route naming do not enforce access control.",
        "security_knowledge",
        "OWASP API Security Top 10 2023: API5 Broken Function Level Authorization",
        source_url=(
            "https://api-security.owasp.org/editions/2023/en/"
            "0xa5-broken-function-level-authorization/"
        ),
        license="CC BY-SA 4.0",
    ),
    _Document(
        "owasp-api7",
        "Server Side Request Forgery",
        "If an API fetches caller-controlled URLs, validate schemes and destinations, block "
        "private and metadata address ranges, and re-check redirects and DNS results.",
        "security_knowledge",
        "OWASP API Security Top 10 2023: API7 Server Side Request Forgery",
        source_url=(
            "https://api-security.owasp.org/editions/2023/en/0xa7-server-side-request-forgery/"
        ),
        license="CC BY-SA 4.0",
    ),
    _Document(
        "owasp-api8",
        "Security Misconfiguration",
        "Review permissive CORS, debug modes, default credentials, unsafe error details, and "
        "inconsistent security headers. Confirm behavior in the deployed environment.",
        "security_knowledge",
        "OWASP API Security Top 10 2023: API8 Security Misconfiguration",
        source_url=(
            "https://api-security.owasp.org/editions/2023/en/0xa8-security-misconfiguration/"
        ),
        license="CC BY-SA 4.0",
    ),
)

_TOKEN_RE = re.compile(r"[a-z0-9_./{}-]+", re.IGNORECASE)
_VECTOR_SIZE = 256
_STOP_WORDS = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "be",
    "by",
    "can",
    "do",
    "for",
    "from",
    "how",
    "i",
    "in",
    "is",
    "it",
    "me",
    "my",
    "of",
    "on",
    "or",
    "our",
    "please",
    "the",
    "this",
    "to",
    "was",
    "what",
    "when",
    "where",
    "which",
    "who",
    "why",
    "with",
}
_QUERY_EXPANSIONS = {
    "access": ("authorization", "ownership", "permission"),
    "another": ("object", "ownership", "tenant"),
    "book": ("object", "resource", "record"),
    "id": ("identifier", "object"),
    "user": ("principal", "caller", "owner"),
    "token": ("authentication", "bearer", "jwt"),
    "limit": ("rate", "resource", "consumption"),
}


def _tokens(text: str) -> tuple[str, ...]:
    return tuple(
        token.lower()
        for token in _TOKEN_RE.findall(text)
        if len(token) > 1 and token.lower() not in _STOP_WORDS
    )


def _features(text: str) -> Counter[str]:
    words = _tokens(text)
    features = Counter(words)
    features.update(f"{left} {right}" for left, right in zip(words, words[1:], strict=False))
    compact = re.sub(r"\s+", " ", text.lower())
    features.update(f"~{compact[index : index + 3]}" for index in range(max(0, len(compact) - 2)))
    return features


def _embedding(features: Counter[str]) -> tuple[float, ...]:
    """Create deterministic signed-hash vectors without a model download or API key."""
    vector = [0.0] * _VECTOR_SIZE
    for feature, weight in features.items():
        digest = hashlib.blake2b(feature.encode("utf-8"), digest_size=8).digest()
        value = int.from_bytes(digest, "big")
        index = value % _VECTOR_SIZE
        sign = 1.0 if value & (1 << 63) else -1.0
        vector[index] += sign * weight
    norm = math.sqrt(sum(value * value for value in vector))
    return tuple(value / norm for value in vector) if norm else tuple(vector)


def _cosine(left: tuple[float, ...], right: tuple[float, ...]) -> float:
    return sum(a * b for a, b in zip(left, right, strict=True))


def _unit_vector(values: list[float]) -> tuple[float, ...] | None:
    if not values or any(not math.isfinite(value) for value in values):
        return None
    norm = math.sqrt(sum(value * value for value in values))
    return tuple(value / norm for value in values) if norm else None


def _make_documents(
    spec_findings: list[dict[str, Any]],
    source_findings: list[dict[str, Any]],
    correlated_findings: list[dict[str, Any]],
    matched_endpoints: list[dict[str, Any]],
) -> tuple[_Document, ...]:
    documents: list[_Document] = []
    for layer, findings in (
        ("specification", spec_findings),
        ("source code", source_findings),
        ("cross-layer", correlated_findings),
    ):
        for index, finding in enumerate(findings):
            endpoint = finding.get("endpoint") or finding.get("matched_endpoint") or {}
            if isinstance(endpoint, dict):
                endpoint_label = " ".join(
                    str(endpoint.get(key) or "")
                    for key in ("spec_method", "spec_path", "source_path", "source_method")
                ).strip()
            else:
                endpoint_label = str(endpoint)
            evidence = finding.get("evidence", [])
            evidence_refs: list[str] = []
            if isinstance(evidence, list):
                evidence_messages: list[str] = []
                for evidence_index, item in enumerate(evidence):
                    if not isinstance(item, dict):
                        continue
                    location = item.get("location")
                    if not isinstance(location, dict):
                        location = {}
                    file_path = item.get("file") or location.get("file")
                    line = item.get("line") or location.get("line")
                    if file_path:
                        reference = f"{file_path}:{line}" if line else str(file_path)
                        evidence_refs.append(
                            f"evidence-{layer}-{index}-{evidence_index} ({reference})"
                        )
                    evidence_messages.append(
                        f"{item.get('message', '')} {file_path or ''} {line or ''}"
                    )
                evidence_text = " ".join(evidence_messages)
            else:
                evidence_text = str(evidence or "")
            content = (
                " ".join(
                    str(finding.get(key, ""))
                    for key in ("title", "rule_id", "rationale", "remediation", "severity")
                )
                + f" {endpoint_label} {evidence_text}"
            )
            title = str(finding.get("title") or finding.get("rule_id") or "Finding")
            documents.append(
                _Document(
                    document_id=f"finding-{layer}-{index}",
                    title=title,
                    content=content.strip(),
                    source_type="scan_finding",
                    citation="; ".join([f"{layer} finding: {title}", *evidence_refs[:3]]),
                    endpoint=endpoint_label or None,
                )
            )

    for index, endpoint in enumerate(matched_endpoints):
        if not isinstance(endpoint, dict):
            continue
        label = f"{endpoint.get('spec_method', '')} {endpoint.get('spec_path', '')}".strip()
        content = " ".join(
            str(endpoint.get(key) or "")
            for key in (
                "spec_method",
                "spec_path",
                "source_method",
                "source_path",
                "handler_name",
                "rationale",
            )
        )
        documents.append(
            _Document(
                document_id=f"endpoint-{index}",
                title=f"Endpoint mapping: {label}",
                content=content,
                source_type="endpoint_mapping",
                citation=f"OpenAPI/source endpoint mapping: {label}",
                endpoint=label or None,
            )
        )
    return tuple(documents) + _SECURITY_KNOWLEDGE


def answer_scan_question(
    query: str,
    *,
    spec_findings: list[dict[str, Any]],
    source_findings: list[dict[str, Any]],
    correlated_findings: list[dict[str, Any]],
    matched_endpoints: list[dict[str, Any]],
    limit: int = 5,
    local_ai_status: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Retrieve scan evidence and security guidance with lexical + vector ranking."""
    documents = _make_documents(
        spec_findings, source_findings, correlated_findings, matched_endpoints
    )
    query_tokens = Counter(_tokens(query))
    for token in tuple(query_tokens):
        for expanded in _QUERY_EXPANSIONS.get(token, ()):
            query_tokens[expanded] += query_tokens[token]
    query_features = _features(query)
    query_embedding = _embedding(query_features)
    doc_features = [_features(doc.title + " " + doc.content) for doc in documents]
    doc_embeddings = [_embedding(features) for features in doc_features]
    embedding_vectors = embed_local_texts(
        [query, *(doc.title + " " + doc.content for doc in documents)],
        status_data=local_ai_status,
    )
    if embedding_vectors and len(embedding_vectors) == len(documents) + 1:
        normalized_vectors = [_unit_vector(vector) for vector in embedding_vectors]
        dimensions_match = len({len(vector) for vector in embedding_vectors}) == 1
        if dimensions_match and all(vector is not None for vector in normalized_vectors):
            query_embedding = normalized_vectors[0] or query_embedding
            doc_embeddings = [
                vector or _embedding(features)
                for vector, features in zip(normalized_vectors[1:], doc_features, strict=True)
            ]
        else:
            embedding_vectors = None
    else:
        embedding_vectors = None

    document_frequency: Counter[str] = Counter()
    for features in doc_features:
        document_frequency.update(features.keys())
    average_length = sum(sum(features.values()) for features in doc_features) / max(
        1, len(doc_features)
    )
    total_docs = len(documents)
    ranked: list[tuple[float, _Document, float, float]] = []
    for document, features, embedding in zip(documents, doc_features, doc_embeddings, strict=True):
        length = sum(features.values())
        bm25 = 0.0
        for token, query_weight in query_tokens.items():
            term_frequency = features.get(token, 0)
            if not term_frequency:
                continue
            inverse_frequency = math.log1p(
                (total_docs - document_frequency[token] + 0.5) / (document_frequency[token] + 0.5)
            )
            denominator = term_frequency + 1.2 * (
                1 - 0.75 + 0.75 * length / max(1.0, average_length)
            )
            bm25 += inverse_frequency * (term_frequency * 2.2 / denominator) * query_weight
        semantic = max(0.0, _cosine(query_embedding, embedding))
        ranked.append((bm25 + semantic * 2.0, document, bm25, semantic))

    ranked.sort(key=lambda item: (-item[0], item[1].document_id))
    selected = [
        (score, document)
        for score, document, lexical_score, semantic_score in ranked
        if lexical_score > 0 or semantic_score >= 0.30
    ][:limit]
    sources = [
        {
            "id": document.document_id,
            "title": document.title,
            "source_type": document.source_type,
            "citation": document.citation,
            "source_url": document.source_url,
            "license": document.license,
            "endpoint": document.endpoint,
            "excerpt": document.content[:700],
            "relevance": round(score, 4),
        }
        for score, document in selected
    ]

    finding_sources = [source for source in sources if source["source_type"] == "scan_finding"]
    if finding_sources:
        statements: list[str] = []
        for source in finding_sources[:3]:
            title = str(source["title"])
            endpoint = source.get("endpoint")
            statements.append(f"{title} ({endpoint})" if endpoint else title)
        answer = (
            "The scan evidence most relevant to your question is: " + "; ".join(statements) + "."
        )
        answer += (
            " Review the cited finding evidence before treating this as a confirmed vulnerability."
        )
    elif sources:
        answer = (
            "I found related endpoint mappings or security guidance, but no directly matching "
            "scan finding. Treat these sources as review guidance, not evidence of a vulnerability."
        )
    else:
        answer = "No relevant scan evidence or security guidance matched that question."

    return {
        "answer": answer,
        "sources": sources,
        "retrieval": (
            "local_hybrid_bm25_ollama_embeddings"
            if embedding_vectors
            else "local_hybrid_bm25_hashed_vector"
        ),
        "external_network_used": False,
        "notice": (
            "Evidence-grounded retrieval only; no hosted language model or external service "
            "was called."
        ),
    }
