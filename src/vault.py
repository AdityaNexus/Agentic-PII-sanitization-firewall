import re
from typing import Dict

class PIIVault:
    def __init__(self):
        self.mapping: Dict[str, str] = {}
    
    def store(self, token: str, value: str) -> None:
        self.mapping[token] = value
    
    def restore(self, text: str) -> str:
        if not self.mapping:
            return text

        # Sort tokens by length descending to match longer tokens first (e.g. [PERSON_10] before [PERSON_1])
        sorted_tokens = sorted(self.mapping.keys(), key=len, reverse=True)
        pattern = re.compile("|".join(re.escape(token) for token in sorted_tokens))

        return pattern.sub(lambda match: self.mapping[match.group(0)], text)

    def get_mapping(self) -> Dict[str, str]:
        return self.mapping.copy()