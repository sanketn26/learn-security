"""Triage practice: what the workshop rules catch, wrongly flag, and miss.

Run:  semgrep --test labs/workshop/semgrep      (checks the annotations below)
      semgrep --config labs/workshop/semgrep/rules.yml labs/notes-api/app.py
"""

import sqlite3


def true_positive(conn: sqlite3.Connection, user: str, q: str):
    # ruleid: workshop-sql-built-from-string
    return conn.execute(f"SELECT id FROM notes WHERE owner = '{user}' AND title LIKE '%{q}%'")


_SORT_COLUMNS = {"title": "title", "id": "id"}


def false_positive(conn: sqlite3.Connection, sort: str):
    # FALSE POSITIVE: `column` can only be one of two literals from the dict
    # above, so this is not injectable. The rule cannot see that. Decide what
    # you would do: suppress with a justification, or restructure so the
    # statement is a constant per branch.
    column = _SORT_COLUMNS.get(sort, "id")
    # ruleid: workshop-sql-built-from-string
    return conn.execute(f"SELECT id FROM notes ORDER BY {column}")


def false_negative(conn: sqlite3.Connection, q: str):
    # FALSE NEGATIVE: the injectable text is assembled over several statements
    # and joined, so no single call matches the rule. This is as injectable as
    # `true_positive`.
    parts = ["owner = 'alice'"]
    parts.append("title LIKE '%" + q + "%'")
    where = " AND ".join(parts)
    # todoruleid: workshop-sql-built-from-string
    return conn.execute("SELECT id FROM notes WHERE " + where)
