from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.agent import app


def main() -> None:
    user_input = input("\nYou: ")

    result = app.invoke({
        "input_text": user_input,

        "safe_text": "",

        "vault_mapping": {},

        "llm_response": "",

        "final_output": "",

        "is_valid": False,

        "retry_count": 0,

        "input_status": "",

        "security_status": "",

        "security_reason": "",

        "detected_issues": [],

        "retry_instruction": "",
    })

    print("\n==============================")
    print("FINAL RESPONSE")
    print("==============================")
    print(result["final_output"])

    print("\nSECURITY STATUS:")
    print(result["security_status"])


if __name__ == "__main__":
    main()