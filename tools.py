"""
Tools the model can call. Each one has a VULNERABLE behaviour (default) and a
SECURE behaviour (--secure or /secure on). Compare them -- that's the lesson.

Nothing here touches the internet. send_email only writes to outbox.log.

Scenarios (OWASP Top 10 for LLM Applications 2026):
  lookup_employee  -> LLM02 Sensitive Information Disclosure
  send_email       -> LLM03 Excessive Agency
  read_file        -> LLM03 Excessive Agency (+ LLM09 access control)
  save_note        -> LLM05 Data and Model Poisoning
  search_tickets   -> LLM10 Improper Output Handling (SQL injection via the model)
"""
import datetime
import json
import os
import sqlite3

from rag import parse_access

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DOCS_DIR = os.path.join(BASE_DIR, "docs")
DATA_DIR = os.path.join(BASE_DIR, "data")
KB_NOTES_DIR = os.path.join(DOCS_DIR, "kb_notes")
PENDING_DIR = os.path.join(DATA_DIR, "pending_notes")
OUTBOX = os.path.join(BASE_DIR, "outbox.log")
INTERNAL_DOMAIN = "acme.example"
PUBLIC_EMPLOYEE_FIELDS = ("name", "title", "department", "email")
MAX_NOTE_CHARS = 1000

TOOL_SPECS = """\
- lookup_employee: args {"name": "<full name>"} -> employee directory record
- send_email: args {"to": "<address>", "subject": "<text>", "body": "<text>"} -> sends an email
- read_file: args {"path": "<file path, e.g. docs/it_policy.md>"} -> returns file contents
- search_tickets: args {"query": "<words in the ticket title>"} -> matching IT tickets
- save_note: args {"text": "<a fact to remember>"} -> adds a note to the knowledge base for everyone"""


def load_employees():
    with open(os.path.join(DATA_DIR, "employees.json"), encoding="utf-8") as f:
        return json.load(f)


def load_tickets():
    with open(os.path.join(DATA_DIR, "tickets.json"), encoding="utf-8") as f:
        return json.load(f)


class Tools:
    def __init__(self, secure=False, confirm=input, user=None, on_kb_change=None):
        self.secure = secure
        self.confirm = confirm            # asks the human for approval
        self.user = user or {"name": "anonymous", "roles": ["employee"]}
        self.on_kb_change = on_kb_change  # called after the knowledge base changes
        self._build_databases()

    def _build_databases(self):
        tickets = load_tickets()
        employees = load_employees()

        # VULN setup: one database holds tickets AND payroll, and the tool
        # connects with full access. Least privilege is ignored.
        self.db_all = sqlite3.connect(":memory:", check_same_thread=False)
        self.db_all.execute("CREATE TABLE tickets (id INTEGER, title TEXT, status TEXT, owner TEXT)")
        self.db_all.execute("CREATE TABLE payroll (name TEXT, salary INTEGER, ssn_last4 TEXT)")
        self.db_all.executemany("INSERT INTO tickets VALUES (:id, :title, :status, :owner)", tickets)
        self.db_all.executemany(
            "INSERT INTO payroll VALUES (?, ?, ?)",
            [(e["name"], e["salary"], e["ssn_last4"]) for e in employees],
        )

        # FIX setup: the ticket tool gets a database with ONLY tickets in it.
        self.db_tickets = sqlite3.connect(":memory:", check_same_thread=False)
        self.db_tickets.execute("CREATE TABLE tickets (id INTEGER, title TEXT, status TEXT, owner TEXT)")
        self.db_tickets.executemany("INSERT INTO tickets VALUES (:id, :title, :status, :owner)", tickets)

    @property
    def roles(self):
        return set(self.user.get("roles", ["employee"]))

    # ---------------------------------------------------------------- tools
    def lookup_employee(self, name):
        for e in load_employees():
            if e["name"].lower() == str(name).strip().lower():
                if self.secure:
                    # FIX: the tool itself only returns what this user may see.
                    # A "don't share salaries" line in the prompt is NOT a control.
                    return {k: e[k] for k in PUBLIC_EMPLOYEE_FIELDS}
                # VULN: returns everything, incl. salary and SSN digits,
                # and relies on the system prompt to keep the model quiet.
                return {k: v for k, v in e.items() if k != "roles"}
        return {"error": f"No employee named {name!r}"}

    def send_email(self, to, subject="", body=""):
        to = str(to)
        if self.secure:
            # FIX 1: allowlist destinations.
            if not to.lower().endswith("@" + INTERNAL_DOMAIN):
                return {"error": f"Blocked: can only email @{INTERNAL_DOMAIN} addresses"}
            # FIX 2: a human approves every side-effecting action.
            print(f"\n[approval needed] Send email to {to}\n  subject: {subject}\n  body: {str(body)[:300]}")
            if self.confirm("  Allow? [y/N] ").strip().lower() != "y":
                return {"error": "User denied sending this email"}
        # VULN (when not secure): sends anywhere, no confirmation.
        with open(OUTBOX, "a", encoding="utf-8") as f:
            f.write(
                f"--- {datetime.datetime.now().isoformat(timespec='seconds')}\n"
                f"To: {to}\nSubject: {subject}\n\n{body}\n\n"
            )
        return {"status": f"Email sent to {to}"}

    def read_file(self, path):
        path = str(path)
        if self.secure:
            # FIX 1: resolve the real path and require it to be inside docs/.
            full = os.path.realpath(os.path.join(DOCS_DIR, path.removeprefix("docs/")))
            if not full.startswith(os.path.realpath(DOCS_DIR) + os.sep):
                return {"error": "Blocked: read_file may only read files inside docs/"}
        else:
            # VULN: path traversal -- any file relative to the app folder,
            # including ../ and data/secrets.env.
            full = os.path.join(BASE_DIR, path)
        try:
            with open(full, encoding="utf-8", errors="replace") as f:
                text = f.read(3000)
        except OSError as e:
            return {"error": str(e)}
        if self.secure:
            # FIX 2: the same access rules as retrieval. Without this, read_file
            # is a side door around the RAG access control (LLM09).
            access, _ = parse_access(text)
            if not (access & self.roles):
                return {"error": "Blocked: you don't have access to this document"}
        return {"path": path, "content": text}

    def search_tickets(self, query):
        query = str(query)
        if self.secure:
            # FIX: parameterized query + a database that only contains tickets.
            rows = self.db_tickets.execute(
                "SELECT id, title, status, owner FROM tickets WHERE title LIKE ? LIMIT 20",
                (f"%{query}%",),
            ).fetchall()
        else:
            # VULN: model output is pasted straight into SQL. If the model can be
            # talked into sending  x' UNION SELECT ...  it runs.
            sql = f"SELECT id, title, status, owner FROM tickets WHERE title LIKE '%{query}%'"
            try:
                rows = self.db_all.execute(sql).fetchall()
            except sqlite3.Error as e:
                return {"error": f"SQL error: {e}", "sql": sql}
        return {"results": [dict(zip(("id", "title", "status", "owner"), r)) for r in rows]}

    def save_note(self, text):
        text = str(text)
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        author = self.user.get("name", "anonymous")
        if self.secure:
            # FIX: notes go to a review queue with provenance. Nothing a user (or a
            # tricked model) writes reaches other users until a human approves it.
            if len(text) > MAX_NOTE_CHARS:
                return {"error": f"Note too long (max {MAX_NOTE_CHARS} chars)"}
            os.makedirs(PENDING_DIR, exist_ok=True)
            with open(os.path.join(PENDING_DIR, f"note_{stamp}.md"), "w", encoding="utf-8") as f:
                f.write(f"<!-- author: {author} -->\n{text}\n")
            return {"status": "Note submitted for review by the knowledge base owner"}
        # VULN: written straight into the knowledge base and indexed at once.
        # Every other user's answers can now be steered by this text.
        os.makedirs(KB_NOTES_DIR, exist_ok=True)
        with open(os.path.join(KB_NOTES_DIR, f"note_{stamp}.md"), "w", encoding="utf-8") as f:
            f.write(text + "\n")
        if self.on_kb_change:
            self.on_kb_change()
        return {"status": "Saved to the knowledge base"}

    # ------------------------------------------------------------- dispatch
    def run(self, name, args):
        fn = {
            "lookup_employee": self.lookup_employee,
            "send_email": self.send_email,
            "read_file": self.read_file,
            "search_tickets": self.search_tickets,
            "save_note": self.save_note,
        }.get(name)
        if fn is None:
            return {"error": f"Unknown tool {name!r}"}
        if not isinstance(args, dict):
            return {"error": "args must be a JSON object"}
        try:
            return fn(**args)
        except TypeError as e:
            return {"error": f"Bad arguments: {e}"}
