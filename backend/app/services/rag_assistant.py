"""Keyless, evidence-grounded hybrid retrieval for scan findings."""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any, cast

from app.services.local_ai import embed_local_texts
from app.services.rag_index import load_index


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
    chunk_id: str | None = None
    source_location: str | None = None
    embedding: tuple[float, ...] | None = None


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
BASELINE_RANKING_POLICY = "hybrid-rrf-k60-v1"
CONSERVATIVE_RANKING_POLICY = "hybrid-rrf-k60-semantic-min-0.50-v1"
DEFAULT_RANKING_POLICY = CONSERVATIVE_RANKING_POLICY
_MIN_SEMANTIC_RELEVANCE = 0.50
_SCAN_CONTEXT_REFERENCE_RE = re.compile(
    r"\b(?:this|the)\s+(?:endpoint|route|finding|vulnerability)\b", re.IGNORECASE
)
_AUTHENTICATION_QUERY_RE = re.compile(r"\b(?:auth\w*|unauthenticated|login|guard)\b", re.I)
_AUTHENTICATION_FINDING_RE = re.compile(
    r"\b(?:API-(?:SOURCE-)?AUTHZ?-\d+|authentication guard|authentication dependency)\b",
    re.I,
)
_AUTHENTICATION_GUIDANCE_TITLE_RE = re.compile(
    r"\b(?:authentication|identity|credential|session)\b", re.I
)
_OBJECT_ACCESS_PROOF_QUERY_RE = re.compile(
    r"\b(?:attacker|another user|account|access(?:ed)?|exploit\w*|prove|proof)\b", re.I
)
_SECRET_DISCLOSURE_VERB_RE = re.compile(
    r"\b(?:reveal|show|print|disclose|expose|share|provide|tell me)\b", re.I
)
_SECRET_DISCLOSURE_TARGET_RE = re.compile(
    r"\b(?:prompts?|instructions?|credentials?|secrets?|api[ _-]?keys?|tokens?)\b", re.I
)
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


def _safe_spec_provenance(value: Any) -> str | None:
    """Retain only bounded OpenAPI JSON Pointers as user-facing evidence references."""
    if not isinstance(value, str) or not value.startswith("spec:/"):
        return None
    if any(ord(character) < 32 for character in value):
        return None
    pointer = value.removeprefix("spec:")
    if any(segment == ".." for segment in pointer.split("/")):
        return None
    return value[:512]


def _make_documents(
    spec_findings: list[dict[str, Any]],
    source_findings: list[dict[str, Any]],
    correlated_findings: list[dict[str, Any]],
    matched_endpoints: list[dict[str, Any]],
    *,
    include_knowledge: bool = True,
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
                    spec_provenance = _safe_spec_provenance(item.get("provenance"))
                    file_reference = (
                        (f"{file_path}:{line}" if line else str(file_path)) if file_path else None
                    )
                    references = [
                        reference for reference in (file_reference, spec_provenance) if reference
                    ]
                    if references:
                        evidence_refs.append(
                            f"evidence-{layer}-{index}-{evidence_index} ({'; '.join(references)})"
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
    return tuple(documents) + (_SECURITY_KNOWLEDGE if include_knowledge else ())


def _documents_from_index(chunks: list[dict[str, Any]]) -> tuple[_Document, ...]:
    documents: list[_Document] = []
    for chunk in chunks:
        raw_vector = chunk.get("embedding")
        vector = (
            tuple(float(value) for value in raw_vector) if isinstance(raw_vector, list) else None
        )
        documents.append(
            _Document(
                document_id=str(chunk["document_id"]),
                title=str(chunk["title"]),
                content=str(chunk["text"]),
                source_type=str(chunk["source_type"]),
                citation=str(chunk.get("source_location") or chunk["document_id"]),
                source_url=str(chunk.get("source_url") or "") or None,
                license=str(chunk.get("license") or "") or None,
                chunk_id=str(chunk["chunk_id"]),
                source_location=str(chunk.get("source_location") or "") or None,
                embedding=vector,
            )
        )
    return tuple(documents)


def answer_scan_question(
    query: str,
    *,
    spec_findings: list[dict[str, Any]],
    source_findings: list[dict[str, Any]],
    correlated_findings: list[dict[str, Any]],
    matched_endpoints: list[dict[str, Any]],
    limit: int = 5,
    local_ai_status: dict[str, Any] | None = None,
    ranking_policy: str = DEFAULT_RANKING_POLICY,
) -> dict[str, Any]:
    """Retrieve scan evidence and security guidance with lexical + vector ranking."""
    if ranking_policy not in {BASELINE_RANKING_POLICY, CONSERVATIVE_RANKING_POLICY}:
        raise ValueError("Unsupported RAG ranking policy.")
    dynamic_documents = _make_documents(
        spec_findings,
        source_findings,
        correlated_findings,
        matched_endpoints,
        include_knowledge=False,
    )
    status_model = str(local_ai_status.get("embedding_model") or "") if local_ai_status else ""
    status_model_digest = (
        str(local_ai_status.get("embedding_model_digest") or "") if local_ai_status else ""
    )
    index_chunks, index_metadata = load_index(
        expected_model_id=status_model or None,
        expected_model_digest=status_model_digest or None,
        expected_embedding_dimensions=(
            local_ai_status.get("embedding_dimensions") if local_ai_status else None
        ),
    )
    knowledge_documents = (
        _documents_from_index(index_chunks) if index_chunks else _SECURITY_KNOWLEDGE
    )
    documents = dynamic_documents + tuple(knowledge_documents)
    query_tokens = Counter(_tokens(query))
    for token in tuple(query_tokens):
        for expanded in _QUERY_EXPANSIONS.get(token, ()):
            query_tokens[expanded] += query_tokens[token]
    query_features = _features(query)
    query_embedding = _embedding(query_features)
    doc_features = [_features(doc.title + " " + doc.content) for doc in documents]
    doc_embeddings = [_embedding(features) for features in doc_features]
    semantic_index_used = False
    if (
        index_metadata.get("status") == "ready"
        and local_ai_status
        and local_ai_status.get("embedding_available") is True
        and index_metadata.get("embedding_model") == status_model
        and (
            not status_model_digest
            or index_metadata.get("embedding_model_digest") == status_model_digest
        )
    ):
        dynamic_batch = dynamic_documents[:128]
        embedding_vectors = embed_local_texts(
            [query, *(doc.title + " " + doc.content for doc in dynamic_batch)],
            status_data=local_ai_status,
        )
        if embedding_vectors and len(embedding_vectors) == len(dynamic_batch) + 1:
            normalized_vectors = [_unit_vector(vector) for vector in embedding_vectors]
            dimensions = index_metadata.get("embedding_dimensions")
            dimensions_match = all(
                vector is not None and len(vector) == dimensions for vector in normalized_vectors
            ) and (
                local_ai_status.get("embedding_dimensions") is None
                or local_ai_status.get("embedding_dimensions") == dimensions
            )
            indexed_vectors_match = all(
                document.embedding is not None and len(document.embedding) == dimensions
                for document in knowledge_documents
            )
            if dimensions_match and indexed_vectors_match:
                query_embedding = cast(tuple[float, ...], normalized_vectors[0])
                for document, vector in zip(dynamic_batch, normalized_vectors[1:], strict=True):
                    if vector is not None:
                        dynamic_index = dynamic_documents.index(document)
                        doc_embeddings[dynamic_index] = vector
                knowledge_offset = len(dynamic_documents)
                doc_embeddings[knowledge_offset:] = [
                    cast(tuple[float, ...], document.embedding) for document in knowledge_documents
                ]
                semantic_index_used = True

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

    ranking_method = "bm25_plus_signed_hash"
    if semantic_index_used:
        # Reciprocal rank fusion avoids treating BM25 and model cosine scores as calibrated
        # probabilities; k=60 is the conventional smoothing constant.
        lexical_ranks = {
            item[1].chunk_id or item[1].document_id: rank
            for rank, item in enumerate(
                sorted(
                    ranked,
                    key=lambda item: (-item[2], item[1].chunk_id or item[1].document_id),
                ),
            )
        }
        semantic_ranks = {
            item[1].chunk_id or item[1].document_id: rank
            for rank, item in enumerate(
                sorted(
                    ranked,
                    key=lambda item: (-item[3], item[1].chunk_id or item[1].document_id),
                ),
            )
        }
        ranked = [
            (
                1.0 / (60 + lexical_ranks[item[1].chunk_id or item[1].document_id])
                + 1.0 / (60 + semantic_ranks[item[1].chunk_id or item[1].document_id]),
                item[1],
                item[2],
                item[3],
            )
            for item in ranked
        ]
        ranking_method = "reciprocal_rank_fusion_k60"

    ranked.sort(key=lambda item: (-item[0], item[1].chunk_id or item[1].document_id))
    if semantic_index_used and ranking_policy == CONSERVATIVE_RANKING_POLICY:
        eligible = [item for item in ranked if item[3] >= _MIN_SEMANTIC_RELEVANCE]
    else:
        # Preserve lexical fallback and the recorded baseline policy. The conservative
        # semantic policy only abstains when real, compatible model vectors are active.
        eligible = [item for item in ranked if item[2] > 0 or item[3] >= 0.30]
    selected = [(score, document) for score, document, _lexical_score, _semantic_score in eligible][
        :limit
    ]
    finding_candidates = [item for item in ranked if item[1].source_type == "scan_finding"]
    query_folded = " ".join(query.casefold().split())
    endpoint_matches = [
        item
        for item in finding_candidates
        if item[1].endpoint and " ".join(item[1].endpoint.casefold().split()) in query_folded
    ]
    # An explicit active-scan reference or exact endpoint mention makes the scan finding
    # relevant by contract. Put the best matching finding first without expanding `limit`.
    prioritized_candidates = endpoint_matches or finding_candidates
    if (
        limit > 0
        and (endpoint_matches or _SCAN_CONTEXT_REFERENCE_RE.search(query))
        and prioritized_candidates
    ):
        prioritized_finding = prioritized_candidates[0]
        selected = [(prioritized_finding[0], prioritized_finding[1])] + [
            item for item in selected if item[1] is not prioritized_finding[1]
        ][: limit - 1]

    auth_question = bool(_AUTHENTICATION_QUERY_RE.search(query))
    if auth_question:
        auth_findings = [
            item
            for item in finding_candidates
            if _AUTHENTICATION_FINDING_RE.search(
                f"{item[1].title} {item[1].document_id} {item[1].content}"
            )
        ]
        if auth_findings:
            auth_guidance = [
                item
                for item in ranked
                if item[1].source_type == "security_knowledge"
                and _AUTHENTICATION_GUIDANCE_TITLE_RE.search(item[1].title)
            ]
            auth_finding_documents = {item[1] for item in auth_findings}
            auth_finding = next(
                (item for item in endpoint_matches if item[1] in auth_finding_documents),
                auth_findings[0],
            )
            selected = [
                (auth_finding[0], auth_finding[1]),
                *[(item[0], item[1]) for item in auth_guidance],
            ]
            selected = selected[:limit]
    sources = [
        {
            "id": document.chunk_id or document.document_id,
            "title": document.title,
            "source_type": document.source_type,
            "citation": document.citation,
            "document_id": document.document_id,
            "chunk_id": document.chunk_id or document.document_id,
            "source_location": document.source_location or document.citation,
            "source_url": document.source_url,
            "license": document.license,
            "endpoint": document.endpoint,
            "excerpt": document.content[:700],
            "relevance": round(score, 4),
            "retrieval_method": "bm25+ollama_embedding" if semantic_index_used else "bm25+hash",
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

    has_auth_finding = any(
        source["source_type"] == "scan_finding"
        and (
            "API-AUTH-" in str(source["excerpt"])
            or "authentication" in str(source["title"]).lower()
        )
        for source in finding_sources
    )
    if auth_question and has_auth_finding:
        answer = (
            "Static analysis did not recognize a supported authentication guard on this route. "
            "That does not prove the endpoint is unauthenticated or publicly reachable; review "
            "route dependencies, upstream middleware, gateway policy, and deployed access controls."
        )

    has_object_ownership_finding = any(
        source["source_type"] == "scan_finding"
        and (
            "AUTHZ" in str(source["excerpt"]).upper()
            or re.search(
                r"\b(?:object[- ]level authorization|ownership|owner predicate)\b",
                str(source["title"]),
                re.I,
            )
        )
        for source in finding_sources
    )
    if _OBJECT_ACCESS_PROOF_QUERY_RE.search(query) and has_object_ownership_finding:
        ownership_finding = next(
            source
            for source in finding_sources
            if "AUTHZ" in str(source["excerpt"]).upper()
            or re.search(
                r"\b(?:object[- ]level authorization|ownership|owner predicate)\b",
                str(source["title"]),
                re.I,
            )
        )
        endpoint = str(ownership_finding.get("endpoint") or "this endpoint")
        finding_title = str(ownership_finding.get("title") or "Object-ownership finding")
        answer = (
            f"{finding_title} flags {endpoint} because static analysis did not recognize an "
            "object-ownership check. "
            "That does not establish that an attacker accessed another user's account; verify "
            "effective authorization in the handler, data-access layer, and upstream controls, "
            "and use audit evidence to determine whether access occurred."
        )

    has_upload_limit_finding = any(
        source["source_type"] == "scan_finding"
        and (
            "API-RESOURCE-001" in str(source["excerpt"])
            or "recognized total size limit" in str(source["title"]).lower()
        )
        for source in finding_sources
    )
    if has_upload_limit_finding:
        answer += (
            " This static evidence does not establish that resource exhaustion occurred or "
            "that the impact is unbounded."
        )

    if _SECRET_DISCLOSURE_VERB_RE.search(query) and _SECRET_DISCLOSURE_TARGET_RE.search(query):
        answer = "I can't reveal hidden prompts, credentials, or secrets. " + answer

    return {
        "answer": answer,
        "sources": sources,
        "retrieval": (
            "local_hybrid_bm25_ollama_embeddings"
            if semantic_index_used
            else "local_hybrid_bm25_hashed_vector"
        ),
        "index_status": index_metadata.get("status", "missing"),
        "index_version": index_metadata.get("index_version"),
        "ranking_method": (
            f"{ranking_method}_semantic_min_0.50"
            if semantic_index_used and ranking_policy == CONSERVATIVE_RANKING_POLICY
            else ranking_method
        ),
        "ranking_policy": ranking_policy,
        "external_network_used": False,
        "notice": (
            "Evidence-grounded retrieval only; no hosted language model or external service "
            "was called."
        ),
    }
