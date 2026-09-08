# src/agent.py
import re
from typing import TypedDict, Dict
from langgraph.graph import StateGraph, END
from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage
from src.sanitizer import DynamicPIIVault

# State schema passed between nodes
class AgentState(TypedDict):
    input_text: str
    safe_text: str
    vault_mapping: Dict[str, str]
    llm_response: str
    final_output: str
    is_valid: bool

# Initialize 4K-Context Conscious Local LLM Client
llm = ChatOpenAI(
    base_url="http://127.0.0.1:8080/v1",
    api_key="not-needed",
    model="qwen2.5",
    temperature=0.2, # Lower temperature for better token adherence
    max_tokens=512   # Prevents generation from exceeding token bounds
)

sanitizer_engine = DynamicPIIVault()

def sanitize_node(state: AgentState):
    safe_text, vault = sanitizer_engine.sanitize(state["input_text"])
    print(f"\n🔒 Anonymized Text:\n{safe_text}")
    print(f"🔑 Dynamic Vault Mapping: {vault}")
    return {"safe_text": safe_text, "vault_mapping": vault}

def reason_node(state: AgentState):
    # Concise System Prompt designed to save context window tokens
    system_prompt = (
        "You are an enterprise AI assistant. Reply politely and helpfully to the user's message.\n"
        "STRICT RULE: You will see placeholder tokens like __PERSON_1__ or __EMAIL_1__.\n"
        "DO NOT modify, translate, or remove these tokens. Copy them EXACTLY as written."
    )
    
    messages = [
        SystemMessage(content=system_prompt),
        HumanMessage(content=state["safe_text"])
    ]
    
    response = llm.invoke(messages).content
    print(f"\n🤖 LLM Draft Output:\n{response}")
    return {"llm_response": response}

def validate_node(state: AgentState):
    """
    Validates if all tokens in vault mapping exist in LLM response.
    If the LLM altered brackets (e.g. [PERSON_1]), repairs them automatically.
    """
    response = state["llm_response"]
    repaired_response = response
    vault = state["vault_mapping"]
    
    all_tokens_present = True
    for token in vault.keys():
        if token not in repaired_response:
            # Fallback repair check: if LLM changed __TOKEN__ to [TOKEN] or <TOKEN>
            clean_name = token.strip("_")
            pattern = re.compile(rf"[\<\[]?{clean_name}[\>\]]?", re.IGNORECASE)
            
            if pattern.search(repaired_response):
                repaired_response = pattern.sub(token, repaired_response)
                print(f"⚠️ Repaired corrupted token format back to: {token}")
            else:
                all_tokens_present = False
                
    return {"llm_response": repaired_response, "is_valid": all_tokens_present}

def deanonymize_node(state: AgentState):
    final_output = DynamicPIIVault.deanonymize(
        state["llm_response"], 
        state["vault_mapping"]
    )
    print(f"\n🔓 Final Restored Output:\n{final_output}")
    return {"final_output": final_output}

# Build LangGraph Workflow
workflow = StateGraph(AgentState)

workflow.add_node("sanitize", sanitize_node)
workflow.add_node("reason", reason_node)
workflow.add_node("validate", validate_node)
workflow.add_node("deanonymize", deanonymize_node)

workflow.set_entry_point("sanitize")
workflow.add_edge("sanitize", "reason")
workflow.add_edge("reason", "validate")
workflow.add_edge("validate", "deanonymize")
workflow.add_edge("deanonymize", END)

app = workflow.compile()