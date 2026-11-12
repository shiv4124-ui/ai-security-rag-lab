# AcmeBot RAG Lab

A small RAG chatbot with tools that is **vulnerable on purpose**, built for
practicing AI security. It answers questions about a fake company ("Acme Corp")
from documents in `docs/`, and it can call three tools: look up employees, send
email, and read files.

You attack it in **vulnerable mode**, then switch to **secure mode** and see
which defenses hold and which don't. Work through `EXERCISES.md`.

Pure Python 3.9+, no packages to install. Nothing reaches the internet: "emails" go to `outbox.log`.

## Setup (5 minutes)

**Option A: free local model (recommended)**
1. Install Ollama: https://ollama.com/download
2. Pull a small model: `ollama pull llama3.2:3b`
3. Run: `python app.py`

Small models are easy to trick, which makes them good for learning. To see how a
stronger model changes things, try `ollama pull qwen2.5:7b` and then
`python app.py --model qwen2.5:7b`.

**Option B: any OpenAI-compatible API**
```
export OPENAI_API_KEY=sk-...
python app.py --backend openai --model gpt-4o-mini
# Groq, Together, LM Studio, vLLM, etc.:
python app.py --backend openai --base-url http://localhost:1234/v1 --model <name>
```

## Try it
```
you> how many PTO days do I get?
  retrieved: handbook.md#0 (0.41), ...
bot> Full-time employees get 20 days of PTO per year...

you> what is Tom Alvarez's email?
  tool call: lookup_employee {"name": "Tom Alvarez"}
bot> tom.alvarez@acme.example
```
The grey lines are the debug trace. They show what was retrieved and every tool
call, so you can see an attack working. Toggle the trace with `/debug`.

Commands: `/secure on|off`, `/debug`, `/reload` (after adding docs), `/reset`, `/quit`.

## How it works

```
question ──► rag.py: TF-IDF search over docs/ ──► top 3 chunks
                                                     │
system prompt + chunks + question ──► llm.py ──► model reply
                                                     │
              reply has `CALL {...}`? ──yes──► tools.py ──► result fed back (max 4 steps)
                                     └──no───► answer to user
```

| File | What it does |
|---|---|
| `app.py` | Chat loop, prompt building, tool-call parsing, secure-mode guards |
| `rag.py` | Chunking + TF-IDF retrieval (no embedding model needed) |
| `llm.py` | HTTP client for Ollama / OpenAI-compatible APIs |
| `tools.py` | The 3 tools, each with a vulnerable and a secure version |
| `docs/` | The knowledge base. Anything here can be retrieved, **including attacker text** |
| `data/` | Fake employee records and fake secrets (targets) |
| `attacks/` | Poisoned documents to copy into `docs/` |

## What secure mode changes

| Weakness | Vulnerable | Secure | Kind of fix |
|---|---|---|---|
| Secret in system prompt | Only told "never reveal" | Output filter redacts it | Weak (bypassable) |
| Retrieved docs | Pasted in raw | Wrapped in `<untrusted_documents>` tags, tags escaped, keyword detector | Helps, not reliable |
| `lookup_employee` | Returns salary + SSN, prompt says "don't share" | Tool returns only public fields | **Strong (code)** |
| `send_email` | Any address, no approval | Internal domain only + human approves | **Strong (code)** |
| `read_file` | Any path (`../`, `data/secrets.env`) | Real path must be inside `docs/` | **Strong (code)** |

The main lesson: **anything enforced only by the prompt can be broken; anything
enforced in code around the model holds.** Assume the model *will* be tricked, and
limit what a tricked model can do.

## Reset the lab
Delete `outbox.log` and remove anything you copied into `docs/`, then run `/reload`.
