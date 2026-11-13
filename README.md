# AcmeBot RAG Lab

A small RAG chatbot with tools that is **vulnerable on purpose**, built for practicing
AI security. It has one hands-on scenario for each risk in the
**OWASP Top 10 for LLM Applications 2026**.

AcmeBot answers questions about a fake company ("Acme Corp") from documents in `docs/`,
and it can call five tools: look up employees, send email, read files, search IT tickets,
and save notes to the knowledge base. Each user has roles (IT, HR, engineering, exec),
and some documents are restricted by role.

You attack it in **vulnerable mode**, then switch to **secure mode** and see which
defenses hold and which don't. Work through `EXERCISES.md`.

Pure Python 3.9+, no packages to install. Nothing reaches the internet:
"emails" go to `outbox.log`.

## Setup (5 minutes)

**Option A: free local model (recommended)**
1. Install Ollama: https://ollama.com/download
2. Pull a small model: `ollama pull llama3.2:3b`
3. Run: `python app.py`

Small models are easy to trick, which makes them good for learning. To see how a
stronger model changes things: `ollama pull qwen2.5:7b`, then `python app.py --model qwen2.5:7b`.

**Option B: any OpenAI-compatible API**
```
export OPENAI_API_KEY=sk-...
python app.py --backend openai --model gpt-4o-mini
# Groq, Together, LM Studio, vLLM, etc.:
python app.py --backend openai --base-url http://localhost:1234/v1 --model <name>
```

**Check the lab works without a model:** `python tests/test_lab.py` runs every scenario
against a fake model that obeys anything and prints a table of which attacks worked in each mode.

## Try it
```
you> how many PTO days do I get?
  retrieved: handbook.md#0 (0.50), ...
bot> Full-time employees get 20 days of PTO per year...

you> what is Tom Alvarez's email?
  tool call: lookup_employee {"name": "Tom Alvarez"}
bot> tom.alvarez@acme.example
```
The grey lines are the debug trace. They show what was retrieved and every tool call,
so you can see an attack working.

| Command | What it does |
|---|---|
| `/secure on\|off` | Turn defenses on or off |
| `/login <name>` / `/whoami` | Switch user: "Tom Alvarez" (IT, default), "Lena Ortiz" (HR), "Dana Lee", "Priya Shah", "Marcus Webb" |
| `/usage` | Model calls, estimated tokens and cost |
| `/export` | Save the chat as `transcript.html` |
| `/review`, `/approve <file>` | Review queue for knowledge-base notes |
| `/model` | Check the model against `data/approved_models.json` |
| `/debug`, `/reload`, `/reset`, `/quit` | Trace on/off, re-index docs, clear history, exit |

## How it works

```
question ──► rag.py: TF-IDF search over docs/ (filtered by role in secure mode) ──► top 3 chunks
                                                                                      │
system prompt + chunks + question ──► llm.py ──► model reply                         │
                                                     │                                │
              reply has `CALL {...}`? ──yes──► tools.py ──► result fed back (step limit)
                                     └──no───► output filter ──► answer to user
```

| File | What it does |
|---|---|
| `app.py` | Chat loop, prompt building, tool-call parsing, limits, output filter, HTML export |
| `rag.py` | Chunking, TF-IDF retrieval, role-based access metadata |
| `llm.py` | HTTP client for Ollama / OpenAI-compatible APIs |
| `tools.py` | The 5 tools, each with a vulnerable and a secure version |
| `docs/` | The knowledge base. Anything here can be retrieved, **including attacker text** |
| `docs/hr_confidential/` | Restricted to HR and exec roles |
| `data/` | Fake employees, tickets, secrets, and the approved-models list |
| `attacks/` | Poisoned documents to copy into `docs/` |
| `tests/test_lab.py` | Offline test of every scenario |

## The 10 scenarios and what secure mode changes

| OWASP 2026 | Vulnerable | Secure | Fix strength |
|---|---|---|---|
| LLM01 Prompt Injection | Retrieved docs pasted in raw | Docs wrapped in tags, tags escaped, keyword detector | Helps, not reliable |
| LLM02 Sensitive Information Disclosure | Tool returns salary + SSN; prompt says "don't share" | Tool returns only public fields | **Strong (code)** |
| LLM03 Excessive Agency | Email anywhere, no approval; read any file | Internal domain only + human approval; `docs/` only | **Strong (code)** |
| LLM04 Supply Chain | Any model runs | Model must be on the allowlist; optional digest pinning | **Strong if pinned** |
| LLM05 Data and Model Poisoning | Notes go straight into the knowledge base | Review queue with author, human approves | **Strong (process)** |
| LLM06 Unbounded Consumption | No limits; 15 tool calls in a row | Input size, output tokens, rate limit, token budget, 4 tool calls | **Strong (code)** |
| LLM07 Misinformation | Answers anything | Low-score warning + `Sources:` line | Helps, not reliable |
| LLM08 Hidden Context Exposure | Secret in prompt, "never reveal" | Output filter redacts the exact string | Weak (bypassable) |
| LLM09 Vector and Embedding Weaknesses | Search ignores who is asking | Filter by role before search; `read_file` checks too | **Strong (code)** |
| LLM10 Improper Output Handling | Model output in raw SQL and raw HTML | Parameterized SQL, least-privilege DB, HTML escaping + CSP | **Strong (code)** |

The main lesson: **anything enforced only by the prompt can be broken; anything enforced
in code around the model holds.** Assume the model *will* be tricked, and limit what a
tricked model can do.

## Reset the lab
See the bottom of `EXERCISES.md`.
