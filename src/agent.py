import os
from typing import TypedDict, Dict, List

from langgraph.graph import StateGraph, END
from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage

from .detector import PIIDetector
from .secret_detector import SecretDetector
from .sanitizer import PIISanitizer
from .vault import PIIVault
from .output_validator import OutputValidator
from .output_repair import OutputRepairer


# ============================================================
# Configuration
# ============================================================

MAX_RETRIES = 3

LLM_BASE_URL = os.getenv("FIREWALL_LLM_BASE_URL", "http://127.0.0.1:8080/v1")
LLM_API_KEY = os.getenv("FIREWALL_LLM_API_KEY", "not-needed")
LLM_MODEL = os.getenv("FIREWALL_LLM_MODEL", "Qwen3-1.7B-Q8_0.gguf")
LLM_TIMEOUT = float(os.getenv("FIREWALL_LLM_TIMEOUT", "60.0"))


# ============================================================
# LangGraph State
# ============================================================

class AgentState(TypedDict):

    # Original user input
    input_text: str

    # Sanitized input sent to LLM
    safe_text: str

    # token -> original PII
    vault_mapping: Dict[str, str]

    # Raw LLM response
    llm_response: str

    # Final response sent to user
    final_output: str

    # Output validation result
    is_valid: bool

    # Number of LLM retries
    retry_count: int

    # Input security status
    input_status: str

    # Overall security status
    security_status: str

    # Explanation for internal use
    security_reason: str

    # Detected security issues
    detected_issues: List[str]

    # Additional instruction used during retry
    retry_instruction: str


# ============================================================
# Local Qwen LLM
# ============================================================

llm = ChatOpenAI(
    base_url=LLM_BASE_URL,
    api_key=LLM_API_KEY,
    model=LLM_MODEL,
    temperature=0.2,
    max_tokens=512,
    timeout=LLM_TIMEOUT,
)


# ============================================================
# Security Components (Shared Instances for Performance)
# ============================================================

shared_pii_detector = PIIDetector()
shared_secret_detector = SecretDetector()
output_repairer = OutputRepairer()

sanitizer_engine = PIISanitizer(
    detector=shared_pii_detector,
    secret_detector=shared_secret_detector
)
output_validator = OutputValidator(
    detector=shared_pii_detector,
    secret_detector=shared_secret_detector
)


# ============================================================
# NODE 1: INPUT SANITIZATION
# ============================================================

def sanitize_node(state: AgentState):

    result = sanitizer_engine.sanitize(
        state["input_text"]
    )

    # --------------------------------------------------------
    # Critical PII / secret detected
    # --------------------------------------------------------

    if result["status"] == "BLOCKED":

        print("\nINPUT BLOCKED")
        print(f"Reason: {result['reason']}")

        detected_issues = [
            detection.entity_type
            for detection in result["detections"]
        ]

        return {
            "safe_text": "",
            "vault_mapping": {},
            "input_status": "BLOCKED",
            "security_status": "BLOCKED",
            "security_reason": result["reason"],
            "detected_issues": detected_issues,
            "final_output": (
                "I'm sorry, but I can't safely process "
                "that request."
            ),
        }

    # --------------------------------------------------------
    # Safe input
    # --------------------------------------------------------

    safe_text = result["safe_text"]
    vault = result["vault"]

    vault_mapping = vault.get_mapping()

    print("\nSANITIZED INPUT:")
    print(safe_text)

    # IMPORTANT:
    # Never print vault_mapping in production.
    # It contains the original PII.

    return {
        "safe_text": safe_text,
        "vault_mapping": vault_mapping,
        "input_status": "SAFE",
        "security_status": "SAFE",
        "security_reason": "",
        "detected_issues": [],
    }


# ============================================================
# ROUTER: AFTER INPUT SANITIZATION
# ============================================================

def route_after_sanitize(state: AgentState):

    if state["input_status"] == "BLOCKED":
        return "block"

    return "reason"


# ============================================================
# NODE 2: LLM REASONING
# ============================================================

def reason_node(state: AgentState):

    system_prompt = (
        "You are an enterprise AI assistant.\n"
        "Answer the user's request clearly and helpfully.\n\n"

        "SECURITY RULES:\n"
        "1. Placeholder tokens represent protected information.\n"
        "2. Never reconstruct the original values behind tokens.\n"
        "3. Never invent or guess protected personal information.\n"
        "4. If you use a placeholder, preserve it exactly.\n"
        "5. Never output raw PII or secrets from protected context.\n"
    )

    messages = [
        SystemMessage(
            content=system_prompt
        ),
        HumanMessage(
            content=state["safe_text"]
        ),
    ]

    # --------------------------------------------------------
    # Add previous response + retry instruction with full context
    # --------------------------------------------------------

    retry_instruction = state.get(
        "retry_instruction",
        ""
    )

    if retry_instruction and state.get("llm_response"):
        messages.append(
            AIMessage(
                content=state["llm_response"]
            )
        )
        messages.append(
            HumanMessage(
                content=retry_instruction
            )
        )
    elif retry_instruction:
        messages.append(
            HumanMessage(
                content=retry_instruction
            )
        )

    # --------------------------------------------------------
    # Call LLM
    # --------------------------------------------------------

    response = llm.invoke(messages).content

    print("\nLLM RESPONSE:")
    print(response)

    return {
        "llm_response": response
    }


# ============================================================
# NODE 3: OUTPUT FIREWALL
# ============================================================

def output_firewall_node(state: AgentState):

    llm_response = state.get("llm_response", "")

    # Auto-repair slightly corrupted or unbracketed placeholders first
    repaired_response = output_repairer.repair(
        response=llm_response,
        vault_mapping=state.get("vault_mapping", {})
    )

    result = output_validator.validate(
        response=repaired_response,
        vault_mapping=state["vault_mapping"],
    )

    detected_issues = []

    # Original PII leaked
    detected_issues.extend(
        result.leaked_values
    )

    # Placeholder corruption
    detected_issues.extend(
        result.corrupted_tokens
    )

    # Newly detected PII
    detected_issues.extend(
        result.detected_pii
    )

    if result.is_safe:

        print("\nOUTPUT FIREWALL: PASSED")

    else:

        print("\nOUTPUT FIREWALL: FAILED")
        print(
            f"Reason: {result.reason}"
        )

    return {
        "llm_response": repaired_response,

        "is_valid": result.is_safe,

        "security_status": (
            "SAFE"
            if result.is_safe
            else "UNSAFE"
        ),

        "security_reason": result.reason,

        "detected_issues": detected_issues,
    }


# ============================================================
# ROUTER: AFTER OUTPUT FIREWALL
# ============================================================

def route_after_output(state: AgentState):

    # --------------------------------------------------------
    # Output is safe
    # --------------------------------------------------------

    if state["is_valid"]:
        return "deanonymize"

    # --------------------------------------------------------
    # Maximum retry reached
    # --------------------------------------------------------

    if state["retry_count"] >= MAX_RETRIES:
        return "block"

    # --------------------------------------------------------
    # Try LLM again
    # --------------------------------------------------------

    return "retry"


# ============================================================
# NODE 4: RETRY
# ============================================================

def retry_node(state: AgentState):

    new_retry_count = (
        state["retry_count"] + 1
    )

    print(
        f"\nSecurity retry "
        f"{new_retry_count}/{MAX_RETRIES}"
    )

    retry_instruction = (
        "Your previous response failed the output "
        "security validation.\n"
        "Generate a new response.\n"
        "Do not reveal any original PII or secrets.\n"
        "Preserve protected placeholder tokens exactly "
        "as provided.\n"
        "Do not attempt to reconstruct protected values."
    )

    return {
        "retry_count": new_retry_count,
        "retry_instruction": retry_instruction,
    }


# ============================================================
# NODE 5: DEANONYMIZATION
# ============================================================

def deanonymize_node(state: AgentState):

    vault = PIIVault()

    # Reconstruct request-scoped vault
    for token, value in state["vault_mapping"].items():

        vault.store(
            token,
            value
        )

    final_output = vault.restore(
        state["llm_response"]
    )

    print("\nFINAL OUTPUT:")
    print(final_output)

    return {
        "final_output": final_output,
        "security_status": "SAFE",
    }


# ============================================================
# NODE 6: BLOCK
# ============================================================

def block_node(state: AgentState):

    print("\nREQUEST BLOCKED")

    return {
        "final_output": (
            "I'm sorry, but I can't safely provide "
            "that response."
        ),
        "security_status": "BLOCKED",
    }


# ============================================================
# BUILD LANGGRAPH
# ============================================================

workflow = StateGraph(AgentState)


# ------------------------------------------------------------
# Register nodes
# ------------------------------------------------------------

workflow.add_node(
    "sanitize",
    sanitize_node
)

workflow.add_node(
    "reason",
    reason_node
)

workflow.add_node(
    "output_firewall",
    output_firewall_node
)

workflow.add_node(
    "retry",
    retry_node
)

workflow.add_node(
    "deanonymize",
    deanonymize_node
)

workflow.add_node(
    "block",
    block_node
)


# ------------------------------------------------------------
# Entry point
# ------------------------------------------------------------

workflow.set_entry_point(
    "sanitize"
)


# ------------------------------------------------------------
# Input firewall routing
# ------------------------------------------------------------

workflow.add_conditional_edges(
    "sanitize",
    route_after_sanitize,
    {
        "reason": "reason",
        "block": "block",
    },
)


# ------------------------------------------------------------
# LLM reasoning
# ------------------------------------------------------------

workflow.add_edge(
    "reason",
    "output_firewall"
)


# ------------------------------------------------------------
# Output firewall routing
# ------------------------------------------------------------

workflow.add_conditional_edges(
    "output_firewall",
    route_after_output,
    {
        "deanonymize": "deanonymize",
        "retry": "retry",
        "block": "block",
    },
)


# ------------------------------------------------------------
# Retry → LLM
# ------------------------------------------------------------

workflow.add_edge(
    "retry",
    "reason"
)


# ------------------------------------------------------------
# Terminal nodes
# ------------------------------------------------------------

workflow.add_edge(
    "deanonymize",
    END
)

workflow.add_edge(
    "block",
    END
)


# ------------------------------------------------------------
# Compile graph
# ------------------------------------------------------------

app = workflow.compile()