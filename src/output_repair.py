import re


class OutputRepairer:

    def repair(
        self,
        response: str,
        vault_mapping: dict[str, str]
    ) -> str:
        if not vault_mapping:
            return response

        repaired = response

        # Sort tokens by inner name length descending to avoid collisions like PERSON_1 matching PERSON_10
        sorted_tokens = sorted(
            vault_mapping.keys(),
            key=lambda t: len(t.strip("[]_")),
            reverse=True
        )

        for token in sorted_tokens:
            token_name = token.strip("[]_")

            # Match corrupted or unbracketed variations of token_name ensuring word boundary
            pattern = re.compile(
                rf"(?<![A-Za-z0-9_])[\[\(<_\s]*"
                rf"{re.escape(token_name)}"
                rf"[\]\)>_\s]*(?![A-Za-z0-9_])",
                re.IGNORECASE
            )

            repaired = pattern.sub(token, repaired)

        return repaired