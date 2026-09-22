"""
SEMANTIC CACHE ENGINE
Sub-15ms vector cache for recurring banking queries.
Eliminates redundant GPU load for standard FAQ and product queries.
"""

from typing import Optional, Dict, Any, List
import math
import time

def cosine_similarity(v1: List[float], v2: List[float]) -> float:
    dot = sum(a * b for a, b in zip(v1, v2))
    norm_a = math.sqrt(sum(a * a for a in v1))
    norm_b = math.sqrt(sum(b * b for b in v2))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)

class SemanticCache:
    def __init__(self, similarity_threshold: float = 0.95):
        self.similarity_threshold = similarity_threshold
        # Stores: tenant_id -> list of entries
        self.cache: Dict[str, List[Dict[str, Any]]] = {}

    def get(self, tenant_id: str, query_embedding: List[float]) -> Optional[Dict[str, Any]]:
        """
        Looks up response with cosine similarity > threshold in the tenant's partition.
        """
        entries = self.cache.get(tenant_id, [])
        best_match = None
        best_score = -1.0

        for entry in entries:
            score = cosine_similarity(query_embedding, entry["embedding"])
            if score > best_score:
                best_score = score
                best_match = entry

        if best_match and best_score >= self.similarity_threshold:
            best_match["cache_score"] = round(best_score, 4)
            return best_match

        return None

    def set(self, tenant_id: str, query: str, query_embedding: List[float], response: str, ttl_sec: int = 86400):
        if tenant_id not in self.cache:
            self.cache[tenant_id] = []
            
        self.cache[tenant_id].append({
            "query": query,
            "embedding": query_embedding,
            "response": response,
            "created_at": time.time(),
            "ttl": ttl_sec
        })
