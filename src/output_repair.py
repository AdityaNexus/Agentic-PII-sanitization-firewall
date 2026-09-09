import re


class OutputRepairer:

    def repair(
        self,
        response: str,
        vault_mapping: dict[str, str]
    ) -> str:

        repaired = response

        for token in vault_mapping:

            token_name = token.strip("[]_")

            pattern = re.compile(
                rf"[\[\]<>_]*"
                rf"{re.escape(token_name)}"
                rf"[\[\]<>_]*",
                re.IGNORECASE
            )

            repaired = pattern.sub(
                token,
                repaired
            )

        return repaired