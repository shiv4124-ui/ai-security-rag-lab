"""
Retrieval part of the RAG app.

How it works:
  1. Load every .md / .txt file in docs/
  2. Split each file into chunks (groups of paragraphs, ~600 chars)
  3. Turn each chunk into a TF-IDF vector (word-importance scores)
  4. For a question, score every chunk by cosine similarity and return the top k

Access control (LLM09 Vector and Embedding Weaknesses):
  A file can start with   <!-- access: hr, exec -->
  to say which roles may see it. Files without the line are open to "employee".
  search(..., allowed_roles=...) filters chunks BEFORE ranking. If you don't pass
  allowed_roles, every chunk is searchable -- that's the vulnerable behaviour.

Pure Python, no packages needed. Real systems usually use embedding models
(e.g. nomic-embed-text via Ollama) plus a vector DB -- see EXERCISES.md.
"""
import math
import os
import re
from collections import Counter

TOKEN_RE = re.compile(r"[a-z0-9]+")
ACCESS_RE = re.compile(r"^\s*<!--\s*access:\s*([\w ,-]+?)\s*-->", re.IGNORECASE)
STOPWORDS = set(
    "a an and are as at be by can do for from has have how i if in is it its "
    "my of on or our so that the their this to was we what when where which "
    "who will with you your".split()
)


def tokenize(text):
    return [t for t in TOKEN_RE.findall(text.lower()) if t not in STOPWORDS]


def chunk_text(text, max_chars=600):
    """Group paragraphs together until a chunk reaches ~max_chars."""
    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()]
    chunks, current = [], ""
    for p in paragraphs:
        if current and len(current) + len(p) > max_chars:
            chunks.append(current)
            current = p
        else:
            current = f"{current}\n\n{p}" if current else p
    if current:
        chunks.append(current)
    return chunks


def parse_access(text):
    m = ACCESS_RE.match(text)
    if not m:
        return {"employee"}, text
    roles = {r.strip().lower() for r in m.group(1).split(",") if r.strip()}
    return roles, text[m.end():]


class Retriever:
    def __init__(self, docs_dir):
        self.docs_dir = docs_dir
        self.chunks = []
        self.idf = {}
        self.reload()

    def reload(self):
        """(Re)index everything in docs_dir. Call after adding files."""
        self.chunks = []
        for root, dirs, files in os.walk(self.docs_dir):
            dirs.sort()
            for name in sorted(files):
                if not name.endswith((".md", ".txt")):
                    continue
                path = os.path.join(root, name)
                with open(path, encoding="utf-8", errors="replace") as f:
                    access, text = parse_access(f.read())
                source = os.path.relpath(path, self.docs_dir).replace(os.sep, "/")
                for i, chunk in enumerate(chunk_text(text)):
                    self.chunks.append({
                        "source": f"{source}#{i}",
                        "text": chunk,
                        "tokens": tokenize(chunk),
                        "access": access,
                    })

        # Inverse document frequency: rare words matter more.
        n = len(self.chunks)
        df = Counter()
        for c in self.chunks:
            df.update(set(c["tokens"]))
        self.idf = {w: math.log((n + 1) / (d + 1)) + 1 for w, d in df.items()}

        for c in self.chunks:
            c["vec"] = self._vectorize(c["tokens"])
        return len(self.chunks)

    def _vectorize(self, tokens):
        tf = Counter(tokens)
        vec = {w: count * self.idf.get(w, 0.0) for w, count in tf.items()}
        norm = math.sqrt(sum(v * v for v in vec.values())) or 1.0
        return {w: v / norm for w, v in vec.items()}

    def search(self, query, k=3, allowed_roles=None):
        """Return up to k chunks as (score, chunk) pairs, best first.

        allowed_roles: set of the current user's roles. None = no filtering (VULN).
        """
        qvec = self._vectorize(tokenize(query))
        scored = []
        for c in self.chunks:
            if allowed_roles is not None and not (c["access"] & allowed_roles):
                continue
            score = sum(qv * c["vec"].get(w, 0.0) for w, qv in qvec.items())
            if score > 0:
                scored.append((score, c))
        scored.sort(key=lambda x: x[0], reverse=True)
        return scored[:k]
