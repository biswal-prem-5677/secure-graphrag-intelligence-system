"""
ClaimVerifier v2: Directed entity-relation, negation, temporal, and structured-triple
verification engine against retrieved knowledge graph context and primary evidence.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field
from app.core.logging import get_logger
from app.schemas.schemas import EvidenceRecord, GraphData, RelationshipStep

logger = get_logger("claim_verifier")


class StructuredClaim(BaseModel):
    subject: str
    relation: str
    object: str
    evidence_id: Optional[str] = None
    negated: bool = False


class ClaimVerificationResult(BaseModel):
    total_claims: int = 0
    supported_claims: List[str] = Field(default_factory=list)
    unsupported_claims: List[str] = Field(default_factory=list)
    partially_supported_claims: List[str] = Field(default_factory=list)
    contradicted_claims: List[str] = Field(default_factory=list)
    verified_claims: List[str] = Field(default_factory=list)
    faithfulness_score: float = 1.0
    grounding_score: float = 1.0
    hallucination_rate: float = 0.0
    is_fully_grounded: bool = True
    is_refusal: bool = False
    sanitized_answer: str = ""


class ClaimVerifier:
    """Validates factual and structured assertions against grounded graph topology and evidence."""

    STOP_WORDS: Set[str] = {
        "a", "an", "the", "and", "or", "but", "if", "then", "of", "in", "on", "at",
        "by", "for", "with", "about", "against", "between", "into", "through", "during",
        "before", "after", "to", "from", "up", "down", "is", "are", "was", "were", "be",
        "been", "being", "have", "has", "had", "do", "does", "did", "can", "could", "will",
        "would", "shall", "should", "may", "might", "must", "this", "these", "those",
        "that", "which", "who", "whom", "whose", "what", "where", "when", "why", "how",
        "all", "any", "both", "each", "few", "more", "most", "other", "some", "such",
        "no", "nor", "not", "only", "own", "same", "so", "than", "too", "very", "s", "t",
        "just", "don", "now", "also", "as", "documented", "corroborated", "reported",
        "confirmed", "observed", "according", "based", "verified", "threat", "intelligence",
        "analysis", "intrusions", "attacks", "campaigns", "malware", "tools", "systems",
        "networks", "servers", "infrastructure", "credentials", "organizations", "actors",
        "files", "data", "targets", "defense", "initial", "access", "operations", "groups",
        "multiple", "primary", "records", "advisory", "incident", "report", "knowledge",
        "graph", "shows", "within", "associated", "specific", "related",
    }

    # Linguistic mapping from action verbs to canonical directed graph relation families
    VERB_TO_RELATION: Dict[str, Set[str]] = {
        "use": {"USES"},
        "uses": {"USES"},
        "used": {"USES"},
        "employ": {"USES"},
        "employs": {"USES"},
        "employed": {"USES"},
        "deploy": {"USES", "CONDUCTS"},
        "deploys": {"USES", "CONDUCTS"},
        "deployed": {"USES", "CONDUCTS"},
        "leverage": {"USES", "EXPLOITS"},
        "leverages": {"USES", "EXPLOITS"},
        "leveraged": {"USES", "EXPLOITS"},
        "utilize": {"USES"},
        "utilizes": {"USES"},
        "utilized": {"USES"},
        "exploit": {"EXPLOITS", "USES"},
        "exploits": {"EXPLOITS", "USES"},
        "exploited": {"EXPLOITS", "USES"},
        "target": {"TARGETS"},
        "targets": {"TARGETS"},
        "targeted": {"TARGETS"},
        "mitigate": {"MITIGATES"},
        "mitigates": {"MITIGATES"},
        "mitigated": {"MITIGATES"},
        "block": {"MITIGATES"},
        "blocks": {"MITIGATES"},
        "blocked": {"MITIGATES"},
        "prevent": {"MITIGATES"},
        "prevents": {"MITIGATES"},
        "prevented": {"MITIGATES"},
        "conduct": {"CONDUCTS", "ATTRIBUTED_TO"},
        "conducts": {"CONDUCTS", "ATTRIBUTED_TO"},
        "conducted": {"CONDUCTS", "ATTRIBUTED_TO"},
        "communicate": {"COMMUNICATES_WITH"},
        "communicates": {"COMMUNICATES_WITH"},
        "communicated": {"COMMUNICATES_WITH"},
        "located": {"LOCATED_IN"},
        "subtechnique": {"SUBTECHNIQUE_OF"},
        "attributed": {"ATTRIBUTED_TO"},
    }

    NEGATION_PATTERN = re.compile(
        r"\b(?:did\s+not|does\s+not|do\s+not|never|not\s+use|not\s+deploy|not\s+target|"
        r"not\s+exploit|not\s+mitigate|no\s+evidence\s+that|cannot|has\s+not|failed\s+to|"
        r"unrelated\s+to)\b",
        re.IGNORECASE,
    )

    def extract_atomic_claims(self, text: str) -> List[str]:
        """Split text into sentence-level atomic assertions."""
        if not text:
            return []
        sentences = re.split(r"(?<=[.!?])\s+", text.strip())
        claims = []
        for s in sentences:
            s_clean = s.strip()
            if len(s_clean) > 10 and not s_clean.lower().startswith("based on verified threat intelligence"):
                claims.append(s_clean)
        return claims if claims else [text.strip()]

    def extract_entity_candidates(self, text: str) -> List[str]:
        """
        Extract named entity candidates and factual tokens:
        - CVEs, IPv4 addresses, ATT&CK IDs (T1xxx, G0xxx, S0xxx, M1xxx, C0xxx)
        - Snake_case synthetic tokens
        - Multi-word or single capitalized entity phrases
        - Standalone 4-digit years
        """
        candidates: List[str] = []

        patterns = [
            r"\bCVE-\d{4}-[\w-]+\b",
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            r"\b[TGSMC]\d{4}(?:\.\d{3})?\b",
            r"\b[a-zA-Z]+_[a-zA-Z0-9_]+\b",
        ]
        for pat in patterns:
            candidates.extend(re.findall(pat, text))

        # Action object targets (e.g. "deployed Stuxnet", "compromise centrifuges")
        action_matches = re.findall(
            r"\b(?:deployed|used|uses|targeted|targets|exploited|exploits|compromise|compromised|mitigates|blocks|stole|exfiltrated)\s+([a-zA-Z0-9_-]{4,})",
            text,
            re.IGNORECASE,
        )
        for am in action_matches:
            if am.lower() not in self.STOP_WORDS and not am.isdigit():
                candidates.append(am)

        # Capitalized proper noun phrases (including internal hyphenated identifiers)
        cap_phrases = re.findall(r"\b(?:[A-Z][a-zA-Z0-9_-]*(?:\s+[A-Z0-9][a-zA-Z0-9_-]*)*)\b", text)
        for cp in cap_phrases:
            words = cp.split()
            cleaned = [w for w in words if w.lower() not in self.STOP_WORDS]
            if not cleaned:
                continue
            phrase = " ".join(cleaned)
            if len(phrase) >= 3:
                candidates.append(phrase)

        # Standalone 4-digit years
        candidates.extend(re.findall(r"\b(?:19\d{2}|20\d{2})\b", text))

        # Deduplicate preserving order
        seen: Set[str] = set()
        deduped: List[str] = []
        for c in candidates:
            cl = c.lower()
            if cl not in seen and cl not in self.STOP_WORDS:
                seen.add(cl)
                deduped.append(c)
        return deduped

    def _build_grounding_index(
        self,
        graph_data: GraphData,
        relationship_paths: List[RelationshipStep],
        evidence_records: List[EvidenceRecord],
    ) -> Dict[str, Any]:
        """Build fast directed & undirected indexes from retrieved subgraph and evidence."""
        canonical_entities: Set[str] = set()
        id_to_name: Dict[str, str] = {}
        name_to_aliases: Dict[str, Set[str]] = {}
        token_index: Set[str] = set()
        directed_edges: Set[Tuple[str, str, str]] = set()
        directed_pairs: Set[Tuple[str, str]] = set()
        connected_pairs: Set[Tuple[str, str]] = set()
        years_and_cves: Set[str] = set()

        for node in graph_data.nodes:
            nl = node.name.lower()
            il = node.id.lower()
            id_to_name[il] = nl
            canonical_entities.add(nl)
            canonical_entities.add(il)
            name_to_aliases.setdefault(nl, {nl, il})

            for tok in re.findall(r"\b(?:19\d{2}|20\d{2}|CVE-\d{4}-[\w-]+)\b", f"{node.name} {node.id}", re.IGNORECASE):
                years_and_cves.add(tok.lower())

            for part in re.split(r"[\s_-]+", nl):
                if len(part) > 2 and part not in self.STOP_WORDS:
                    token_index.add(part)

            props = getattr(node, "properties", {}) or {}
            if isinstance(props, dict):
                props_str = " ".join(str(v) for v in props.values())
                for tok in re.findall(r"\b(?:19\d{2}|20\d{2}|CVE-\d{4}-[\w-]+)\b", props_str, re.IGNORECASE):
                    years_and_cves.add(tok.lower())
                for alias in props.get("aliases", []):
                    al = str(alias).lower()
                    canonical_entities.add(al)
                    name_to_aliases[nl].add(al)
                    for p in re.split(r"[\s_-]+", al):
                        if len(p) > 2 and p not in self.STOP_WORDS:
                            token_index.add(p)

        def _expand_aliases(term: str) -> Set[str]:
            tl = term.lower()
            resolved = id_to_name.get(tl, tl)
            res = {tl, resolved}
            if resolved in name_to_aliases:
                res.update(name_to_aliases[resolved])
            return res

        # Index directed relationship paths
        for step in relationship_paths:
            s_terms = _expand_aliases(step.source)
            t_terms = _expand_aliases(step.target)
            rel_u = step.relation.upper()
            canonical_entities.update(s_terms | t_terms)
            for s in s_terms:
                for t in t_terms:
                    directed_edges.add((s, rel_u, t))
                    directed_pairs.add((s, t))
                    connected_pairs.add((s, t))
                    connected_pairs.add((t, s))

        # Index raw edges (resolving node IDs to names/aliases)
        for edge in graph_data.edges:
            s_terms = _expand_aliases(edge.source)
            t_terms = _expand_aliases(edge.target)
            rel_u = edge.type.upper()
            for s in s_terms:
                for t in t_terms:
                    directed_edges.add((s, rel_u, t))
                    directed_pairs.add((s, t))
                    connected_pairs.add((s, t))
                    connected_pairs.add((t, s))

        # Index evidence records
        evidence_text: str = ""
        evidence_summaries: List[str] = []
        evidence_titles: Set[str] = set()
        evidence_by_id: Dict[str, str] = {}
        for ev in evidence_records:
            ev_low = f"{ev.title} {ev.summary} {ev.source_id} {ev.date or ''}".lower()
            canonical_entities.add(ev.title.lower())
            canonical_entities.add(ev.source_id.lower())
            evidence_titles.add(ev.title.lower())
            evidence_titles.add(ev.source_id.lower())
            evidence_by_id[ev.source_id.lower()] = ev_low
            evidence_summaries.append(ev_low)
            evidence_text += f" {ev_low}"
            for tok in re.findall(r"\b(?:19\d{2}|20\d{2}|CVE-\d{4}-[\w-]+)\b", ev_low, re.IGNORECASE):
                years_and_cves.add(tok.lower())
            for part in re.findall(r"\b[a-zA-Z0-9_-]{3,}\b", ev.summary.lower()):
                if part not in self.STOP_WORDS:
                    token_index.add(part)

        # Intra-node property co-occurrence (e.g., WinRAR + CVE-2023-38831 on same Vulnerability node)
        for node in graph_data.nodes:
            n_name = node.name.lower()
            props = getattr(node, "properties", {}) or {}
            node_terms = [n_name, node.id.lower()]
            # Extract CVE or ATT&CK ID substrings inside compound names (e.g. "WinRAR CVE-2023-38831")
            for sub_id in re.findall(r"\b(?:CVE-\d{4}-[\w-]+|[TGSMC]\d{4}(?:\.\d{3})?)\b", n_name, re.IGNORECASE):
                node_terms.append(sub_id.lower())
            if isinstance(props, dict):
                for alias in props.get("aliases", []):
                    node_terms.append(str(alias).lower())
                for s in [props.get("software"), props.get("cve_id")]:
                    if s:
                        node_terms.append(str(s).lower())
            for i, t1 in enumerate(node_terms):
                for t2 in node_terms[i + 1 :]:
                    connected_pairs.add((t1, t2))
                    connected_pairs.add((t2, t1))

        return {
            "canonical_entities": canonical_entities,
            "token_index": token_index,
            "directed_edges": directed_edges,
            "directed_pairs": directed_pairs,
            "connected_pairs": connected_pairs,
            "years_and_cves": years_and_cves,
            "evidence_text": evidence_text,
            "evidence_summaries": evidence_summaries,
            "evidence_titles": evidence_titles,
            "evidence_by_id": evidence_by_id,
        }

    def _detect_verb_relation(self, text_between: str) -> Optional[Set[str]]:
        """Detect expected relation family from text connecting Subject and Object."""
        tokens = re.findall(r"[a-zA-Z]+", text_between.lower())
        for tok in tokens:
            if tok in self.VERB_TO_RELATION:
                return self.VERB_TO_RELATION[tok]
        return None

    def _matches_entity_strict(self, ent_low: str, index: Dict[str, Any]) -> bool:
        """Strict entity check: canonical node/alias or verbatim appearance in cited evidence."""
        if ent_low in index["canonical_entities"] or ent_low in index["evidence_text"]:
            return True
        if any(ent_low == c or (len(ent_low) >= 4 and ent_low in c) for c in index["canonical_entities"]):
            return True
        # Require all non-stopword multi-word parts to exist in canonical entity names, not random text
        parts = [p for p in ent_low.split() if p not in self.STOP_WORDS and len(p) > 2]
        if len(parts) >= 2:
            if any(all(p in c for p in parts) for c in index["canonical_entities"]):
                return True
        return False

    def verify_structured_claim(self, claim: StructuredClaim, index: Dict[str, Any]) -> Tuple[bool, str]:
        """Verify an explicit (subject, relation, object, evidence_id, negated) triple."""
        s = claim.subject.lower().strip()
        o = claim.object.lower().strip()
        r = claim.relation.upper().strip()

        if not self._matches_entity_strict(s, index):
            return False, f"Unknown subject entity: {claim.subject}"
        if not self._matches_entity_strict(o, index):
            return False, f"Unknown object entity: {claim.object}"

        has_directed = (s, r, o) in index["directed_edges"] or any(
            s in src and o in tgt and rel == r for (src, rel, tgt) in index["directed_edges"]
        )
        has_reversed = (o, r, s) in index["directed_edges"] or any(
            o in src and s in tgt and rel == r for (src, rel, tgt) in index["directed_edges"]
        )

        if claim.negated:
            if has_directed or (s, o) in index["directed_pairs"]:
                return False, f"Negation contradiction: graph confirms ({claim.subject})-[{r}]->({claim.object})"
            return True, "Valid negative assertion not contradicted by graph"

        if has_reversed and not has_directed:
            return False, f"Direction reversal: graph has ({claim.object})-[{r}]->({claim.subject}), not reverse"

        if not has_directed:
            return False, f"Unverified directed triple ({claim.subject})-[{r}]->({claim.object})"

        if claim.evidence_id:
            ev_id = claim.evidence_id.lower()
            if ev_id not in index["evidence_by_id"]:
                return False, f"Unverified evidence citation: {claim.evidence_id}"

        return True, "Verified directed triple"

    def verify_claim(
        self,
        claim: str,
        index: Dict[str, Any],
    ) -> Tuple[bool, str]:
        """
        Verifies an atomic claim against the grounding index checking:
          1. Refusal awareness
          2. Strict entity existence (unknown proper nouns fail by default)
          3. Verbatim year/CVE grounding
          4. Negation flip detection
          5. Directed relation & path alignment
        """
        claim_clean = claim.strip()
        claim_lower = claim_clean.lower()

        if (
            "insufficient evidence" in claim_lower
            or "could not establish" in claim_lower
            or "no verified" in claim_lower
            or "no records found" in claim_lower
        ):
            return True, "Valid refusal statement"

        # 1. Explicit Year / CVE Grounding Check (must appear in evidence/node properties)
        asserted_years_cves = re.findall(r"\b(?:19\d{2}|20\d{2}|CVE-\d{4}-[\w-]+)\b", claim_clean, re.IGNORECASE)
        for yc in asserted_years_cves:
            ycl = yc.lower()
            if ycl not in index["years_and_cves"] and ycl not in index["evidence_text"]:
                return False, f"Ungrounded temporal/CVE assertion: {yc}"

        # Extract and strictly ground entity candidates
        entities = self.extract_entity_candidates(claim_clean)
        evidence_titles = index.get("evidence_titles", set())
        if not entities:
            # Also check if lowercase canonical entities appear before falling back to generic token ratio
            low_hits = [
                c for c in index["canonical_entities"]
                if len(c) >= 4 and c not in evidence_titles and re.search(r"(?<!\w)" + re.escape(c) + r"(?!\w)", claim_lower)
            ]
            if not low_hits:
                words = [w for w in re.findall(r"\b[a-zA-Z0-9_-]{3,}\b", claim_lower) if w not in self.STOP_WORDS]
                if not words:
                    return True, "No verifiable factual claims"
                grounded_words = [w for w in words if w in index["token_index"] or w in index["evidence_text"]]
                ratio = len(grounded_words) / len(words)
                return (ratio >= 0.60, f"Token grounding ratio: {ratio:.2f}")
            entities = low_hits

        # Also detect lowercase canonical entities present in claim_lower via word boundaries
        present_low_entities: List[str] = list(entities)
        existing_low = {e.lower() for e in present_low_entities}
        for cent in index["canonical_entities"]:
            if len(cent) >= 4 and cent not in existing_low and cent not in evidence_titles:
                if re.search(r"(?<!\w)" + re.escape(cent) + r"(?!\w)", claim_lower):
                    present_low_entities.append(cent)
                    existing_low.add(cent)

        grounded_entities: List[str] = []
        ungrounded_entities: List[str] = []

        for ent in present_low_entities:
            if self._matches_entity_strict(ent.lower(), index):
                grounded_entities.append(ent)
            else:
                ungrounded_entities.append(ent)

        if ungrounded_entities:
            return False, f"Ungrounded entity hallucination: {', '.join(ungrounded_entities)}"

        # Separate cited source names from subject/object entities
        subject_object_entities: List[str] = []
        for ent in grounded_entities:
            ent_low = ent.lower()
            if re.fullmatch(r"(?:19|20)\d{2}", ent_low):
                continue
            ent_toks = [t for t in ent_low.split() if len(t) >= 2]
            is_citation = any(
                ent_low in t or t in ent_low or (ent_toks and all(tok in t for tok in ent_toks))
                for t in evidence_titles
            )
            if is_citation and not any(ent_low in p[0] or ent_low in p[1] for p in index["connected_pairs"]):
                continue
            subject_object_entities.append(ent)

        # 3. Negation Flip & Directed Relation Alignment
        is_negated = bool(self.NEGATION_PATTERN.search(claim_clean))

        if len(subject_object_entities) >= 2:
            e1 = subject_object_entities[0].lower()
            e2 = subject_object_entities[1].lower()

            # Only treat e1 and e2 as identical if they refer to the same entity and are NOT distinct connected nodes
            if e1 == e2:
                return True, "Grounded in knowledge graph"

            # Check entity positions in claim to infer directed order (Subject -> Object)
            pos1 = claim_lower.find(e1)
            pos2 = claim_lower.find(e2)
            subj, obj = (e1, e2) if (pos1 != -1 and pos2 != -1 and pos1 <= pos2) else (e2, e1)

            # Determine expected relation type from verb between Subject and Object
            between_text = claim_lower[min(pos1, pos2) + len(subj) : max(pos1, pos2)] if (pos1 != -1 and pos2 != -1) else claim_lower
            expected_rels = self._detect_verb_relation(between_text)

            def _pair_matches_dir(a: str, b: str, rel_filter: Optional[Set[str]] = None) -> bool:
                for src, rel, tgt in index["directed_edges"]:
                    src_ok = (a == src or (len(a) >= 4 and a in src) or (len(src) >= 4 and src in a))
                    tgt_ok = (b == tgt or (len(b) >= 4 and b in tgt) or (len(tgt) >= 4 and tgt in b))
                    if src_ok and tgt_ok:
                        if rel_filter is None or rel in rel_filter:
                            return True
                return False

            pair_connected = (
                (subj, obj) in index["connected_pairs"]
                or _pair_matches_dir(subj, obj, None)
                or _pair_matches_dir(obj, subj, None)
                or any(
                    (subj in ev and obj in ev)
                    for ev in index.get("evidence_summaries", [])
                )
            )

            # Check Negation Flip: claim negates a confirmed connection
            if is_negated and pair_connected:
                return False, f"Negation contradiction: graph confirms relationship between '{subj}' and '{obj}'"

            # Check Direction Reversal when a directional action verb was asserted
            if expected_rels and len(index["directed_edges"]) > 0:
                forward_ok = _pair_matches_dir(subj, obj, expected_rels)
                reverse_exists = _pair_matches_dir(obj, subj, expected_rels)
                if not forward_ok and reverse_exists:
                    return False, f"Direction reversal: graph supports '{obj} -> {list(expected_rels)[0]} -> {subj}', not reverse"

                # Check Relation Type Mismatch (connected, but via incompatible relation)
                any_forward_dir = _pair_matches_dir(subj, obj, None)
                if any_forward_dir and not forward_ok:
                    # Only fail if MITIGATES/TARGETS/EXPLOITS/USES strictly contradicts the asserted verb
                    actual_rels = {
                        rel for src, rel, tgt in index["directed_edges"]
                        if (subj in src or src in subj) and (obj in tgt or tgt in obj)
                    }
                    if actual_rels and expected_rels.isdisjoint(actual_rels):
                        return False, f"Relation mismatch: asserted {list(expected_rels)}, graph has {list(actual_rels)}"

            if not pair_connected and not is_negated:
                return False, f"Unverified relationship between '{subject_object_entities[0]}' and '{subject_object_entities[1]}'"

        return True, "Grounded in knowledge graph"

    def verify_answer(
        self,
        answer: str,
        graph_data: GraphData,
        relationship_paths: List[RelationshipStep],
        evidence_records: List[EvidenceRecord],
    ) -> ClaimVerificationResult:
        """
        Verify an entire generated answer by decomposing it into atomic claims,
        validating entities, directed relations, negation, and temporal/CVE facts,
        and explicitly tagging refusals independently of answered faithfulness.
        """
        if (
            "insufficient evidence" in answer.lower()
            or "could not establish" in answer.lower()
            or (not graph_data.nodes and not evidence_records)
        ):
            return ClaimVerificationResult(
                total_claims=1,
                supported_claims=[answer],
                unsupported_claims=[],
                verified_claims=[answer],
                faithfulness_score=1.0,
                grounding_score=1.0,
                hallucination_rate=0.0,
                is_fully_grounded=True,
                is_refusal=True,
                sanitized_answer=answer,
            )

        claims = self.extract_atomic_claims(answer)
        if not claims:
            return ClaimVerificationResult()

        index = self._build_grounding_index(graph_data, relationship_paths, evidence_records)

        supported: List[str] = []
        unsupported: List[str] = []
        contradicted: List[str] = []

        for claim in claims:
            is_supp, reason = self.verify_claim(claim, index)
            if is_supp:
                supported.append(claim)
            else:
                unsupported.append(claim)
                if "contradiction" in reason.lower() or "direction reversal" in reason.lower():
                    contradicted.append(claim)
                logger.info("claim_unsupported", claim=claim, reason=reason)

        total = len(claims)
        supp_count = len(supported)
        unsupp_count = len(unsupported)

        faithfulness = round(supp_count / total, 2) if total > 0 else 1.0
        hallucination_rate = round(unsupp_count / total, 2) if total > 0 else 0.0
        sanitized = " ".join(supported) if supported else answer

        return ClaimVerificationResult(
            total_claims=total,
            supported_claims=supported,
            unsupported_claims=unsupported,
            partially_supported_claims=[],
            contradicted_claims=contradicted,
            verified_claims=supported,
            faithfulness_score=faithfulness,
            grounding_score=faithfulness,
            hallucination_rate=hallucination_rate,
            is_fully_grounded=(unsupp_count == 0),
            is_refusal=False,
            sanitized_answer=sanitized,
        )


claim_verifier = ClaimVerifier()
