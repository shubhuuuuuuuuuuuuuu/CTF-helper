from __future__ import annotations

import math
import re
from collections import Counter


COMMON_WORDS = {
    "a", "about", "after", "all", "an", "and", "are", "as", "at", "be", "been", "before", "between", "both",
    "but", "by", "can", "color", "could", "day", "do", "door", "down", "each", "else", "for", "from",
    "get", "good", "have", "hello", "here", "hidden", "how", "if", "in", "into", "is", "it", "know",
    "like", "look", "make", "many", "message", "more", "most", "much", "must", "new", "no", "not", "of",
    "on", "one", "or", "other", "our", "out", "over", "people", "question", "room", "said", "see", "secret",
    "she", "so", "some", "such", "test", "than", "that", "the", "their", "them", "then", "there", "these",
    "they", "this", "time", "to", "up", "was", "way", "we", "well", "were", "what", "when", "which", "who",
    "will", "with", "would", "you", "your",
}
COMMON_BIGRAMS = set("th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se ha as ou io le ve co me de hi ri ro ic ne ea ra ce li ch ll be ma si om ur ca el ta la ns di fo ho pe ec pr no us ac ot il tr ly nc et ut ss so rs un lo wa ge ie wh ee wi em ad ol rt we gh".split())


def english_score(text: str) -> float:
    letters = [c.lower() for c in text if c.isalpha()]
    if not letters: return 0.0
    counts = Counter(letters)
    common = sum(counts[c] for c in "etaoinshrd") / len(letters)
    tokens = re.findall(r"[a-z]+", text.lower())
    word_coverage = sum(token in COMMON_WORDS for token in tokens) / max(1, len(tokens))
    letters_only = "".join(letters)
    bigrams = [letters_only[index:index + 2] for index in range(len(letters_only) - 1)]
    bigram_score = sum(pair in COMMON_BIGRAMS for pair in bigrams) / max(1, len(bigrams))
    structure = sum(c.isalpha() for c in text) / max(1, len(text))
    return min(1.0, max(0.0, common * 0.15 + word_coverage * 0.50 + bigram_score * 0.25 + structure * 0.10))


def index_of_coincidence(text: str) -> float:
    letters = [c.lower() for c in text if c.isalpha()]
    n = len(letters)
    if n < 2: return 0.0
    counts = Counter(letters)
    return sum(v * (v-1) for v in counts.values()) / (n * (n-1))


def xor_single_byte(data: bytes) -> list[tuple[float, int, str]]:
    candidates = []
    for key in range(256):
        raw = bytes(b ^ key for b in data)
        text = raw.decode("utf-8", "replace")
        printable = sum(c.isprintable() or c in "\n\r\t" for c in text) / max(1, len(text))
        score = english_score(text) * 0.7 + printable * 0.3
        if printable > 0.8: candidates.append((score, key, text))
    return sorted(candidates, reverse=True)[:5]
