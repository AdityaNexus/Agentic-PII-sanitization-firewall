from src.agent import app


def main():

    print("=" * 60)
    print("   AGENTIC PII SANITIZATION FIREWALL")
    print("=" * 60)

    print("\nType 'exit' to quit.\n")

    while True:

        user_input = input("👤 You: ")

        if user_input.lower() == "exit":
            break

        if not user_input.strip():
            continue

        try:

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

            print("\n" + "-" * 60)

            print("🤖 Firewall Response:")
            print(result["final_output"])

            print("\n🛡️ Security Status:")
            print(result["security_status"])

            print("-" * 60)

        except Exception as e:

            print("\n❌ Firewall Error:")
            print(type(e).__name__)
            print(str(e))


if __name__ == "__main__":
    main()