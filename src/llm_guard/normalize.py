"""Conservative canonicalization for common text-obfuscation tricks."""

import unicodedata

_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\ufeff"), None)
_LEET = str.maketrans({"0": "o", "1": "i", "!": "i", "3": "e", "4": "a", "@": "a", "5": "s", "$": "s", "7": "t"})


def normalize(text: str) -> str:
    """Normalize Unicode and common leetspeak while preserving character count when possible."""
    canonical = unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH).casefold()
    # Apply substitutions only to alphabetic words; digits in tokens and ordinary prose remain intact.
    words: list[str] = []
    for token in canonical.split():
        if any(char.isalpha() for char in token):
            token = token.translate(_LEET)
        words.append(token)
    return " ".join(words)
