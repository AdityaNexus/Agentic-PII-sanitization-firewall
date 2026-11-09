# Agentic PII Sanitization Firewall

An agentic privacy layer that detects personally identifiable information (PII), replaces it with dynamic placeholders before an LLM call, validates that the placeholders survive the response, and restores the original values only after the response has passed validation.

The project is designed for local or self-hosted LLM deployments where sensitive user data should not be sent directly to the model.

## How it works

```text
User input
    │
    ▼
Presidio PII detection
    │
    ▼
Dynamic placeholder vault
(__PERSON_1__, __EMAIL_1__, ...)
    │
    ▼
Local LLM reasoning through an OpenAI-compatible endpoint
    │
    ▼
Placeholder validation and repair
    │
    ▼
PII restoration
    │
    ▼
Final response
```

The workflow is implemented with LangGraph:

1. **Sanitize** — Presidio identifies PII and creates a per-request token-to-value vault.
2. **Reason** — the LLM receives only the sanitized text and is instructed to preserve tokens exactly.
3. **Validate** — the response is checked for missing or altered tokens, with limited format repair.
4. **De-anonymize** — validated tokens are mapped back to their original values.

## Example

Input:

```text
Hello, my name is Alice Smith. My email is alice.smith@example.com
and my phone number is 555-0199.
```

The model receives a sanitized form similar to:

```text
Hello, my name is __PERSON_1__. My email is __EMAIL_1__
and my phone number is __PHONE_NUMBER_1__.
```

The final response can then be restored for the user without exposing the original PII to the LLM.

## Requirements

- Python 3.11+
- [`uv`](https://docs.astral.sh/uv/)
- A local or self-hosted chat model exposing an OpenAI-compatible API
- An English spaCy model supported by Presidio, such as `en_core_web_lg`

## Setup

```bash
uv sync
uv run python -m spacy download en_core_web_lg
```

By default, the application connects to:

```text
http://127.0.0.1:8080/v1
```

The model name is configured as `qwen2.5` in `src/agent.py`. Update `base_url` and `model` there to match your local inference server.

## Run

Start your OpenAI-compatible local model server on port `8080`, then run:

```bash
uv run python main.py
```

The demo prints the original input, sanitized text, vault mapping, LLM draft, validation status, and restored output.

## Project structure

```text
.
├── main.py              # Runnable demonstration
├── src/
│   ├── agent.py         # LangGraph workflow and local LLM integration
│   └── sanitizer.py     # Presidio detection and token vault
├── pyproject.toml       # Project metadata and dependencies
└── uv.lock              # Reproducible dependency lockfile
```

## Security considerations

- The vault is held in application memory for the current request and is not encrypted or persisted.
- The LLM endpoint must be trusted and configured to avoid request/response logging of sensitive data.
- Validation helps prevent token loss or corruption; it is not a substitute for authorization, access controls, or a full DLP policy.
- Review and extend Presidio recognizers for the PII types and jurisdictions relevant to your application.

## License

No license has been specified yet.
