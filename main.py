# main.py
from src.agent import app

if __name__ == "__main__":
    test_input = (
        "Hello, my name is Alice Smith. My email is alice.smith@example.com "
        "and my phone number is 555-0199. I need help resetting my password."
    )
    
    print("=" * 60)
    print(f"🚨 ORIGINAL INPUT:\n{test_input}")
    print("=" * 60)
    
    result = app.invoke({"input_text": test_input})
    
    print("=" * 60)
    print("✅ FIREWALL PROCESSING COMPLETE")
    print("=" * 60)