"""
Tools the model can call. Each one has a VULNERABLE behaviour (default) and a
SECURE behaviour (--secure or /secure on). Compare them -- that's the lesson.

Nothing here touches the internet. send_email only writes to outbox.log.
"""
import datetime
import json
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DOCS_DIR = os.path.join(BASE_DIR, "docs")
DATA_DIR = os.path.join(BASE_DIR, "data")
OUTBOX = os.path.join(BASE_DIR, "outbox.log")
INTERNAL_DOMAIN = "acme.example"
PUBLIC_EMPLOYEE_FIELDS = ("name", "title", "department", "email")

TOOL_SPECS = """\
- lookup_employee: args {"name": "<full name>"} -> employee directory record
- send_email: args {"to": "<address>", "subject": "<text>", "body": "<text>"} -> sends an email
- read_file: args {"path": "<file path, e.g. docs/it_policy.md>"} -> returns file contents"""


class Tools:
    def __init__(self, secure=False, confirm=input):
        self.secure = secure
        self.confirm = confirm  # function used to ask the human for approval

    # ---------------------------------------------------------------- tools
    def lookup_employee(self, name):
        with open(os.path.join(DATA_DIR, "employees.json"), encoding="utf-8") as f:
            employees = json.load(f)
        for e in employees:
            if e["name"].lower() == str(name).strip().lower():
                if self.secure:
                    # FIX: the tool itself only returns what this user may see.
                    # A "don't share salaries" line in the prompt is NOT a control.
                    return {k: e[k] for k in PUBLIC_EMPLOYEE_FIELDS}
                # VULN: returns everything, incl. salary and SSN digits,
                # and relies on the system prompt to keep the model quiet.
                return e
        return {"error": f"No employee named {name!r}"}

    def send_email(self, to, subject="", body=""):
        to = str(to)
        if self.secure:
            # FIX 1: allowlist destinations.
            if not to.lower().endswith("@" + INTERNAL_DOMAIN):
                return {"error": f"Blocked: can only email @{INTERNAL_DOMAIN} addresses"}
            # FIX 2: a human approves every side-effecting action.
            print(f"\n[approval needed] Send email to {to}\n  subject: {subject}\n  body: {body[:300]}")
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
            # FIX: resolve the real path and require it to be inside docs/.
            full = os.path.realpath(os.path.join(DOCS_DIR, path.removeprefix("docs/")))
            if not full.startswith(os.path.realpath(DOCS_DIR) + os.sep):
                return {"error": "Blocked: read_file may only read files inside docs/"}
        else:
            # VULN: path traversal -- any file relative to the app folder,
            # including ../ and data/secrets.env.
            full = os.path.join(BASE_DIR, path)
        try:
            with open(full, encoding="utf-8", errors="replace") as f:
                return {"path": path, "content": f.read(3000)}
        except OSError as e:
            return {"error": str(e)}

    # ------------------------------------------------------------- dispatch
    def run(self, name, args):
        fn = {
            "lookup_employee": self.lookup_employee,
            "send_email": self.send_email,
            "read_file": self.read_file,
        }.get(name)
        if fn is None:
            return {"error": f"Unknown tool {name!r}"}
        if not isinstance(args, dict):
            return {"error": "args must be a JSON object"}
        try:
            return fn(**args)
        except TypeError as e:
            return {"error": f"Bad arguments: {e}"}
