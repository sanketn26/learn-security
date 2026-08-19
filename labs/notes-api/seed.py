"""Idempotent seed data for the lab notes API."""

USERS = [
    {
        "username": "alice",
        "password": "alice-lab-password",
        "role": "user",
    },
    {
        "username": "bob",
        "password": "bob-lab-password",
        "role": "user",
    },
    {
        "username": "admin",
        "password": "admin-lab-password",
        "role": "admin",
    },
]

NOTES = [
    {
        "id": 1,
        "owner": "alice",
        "title": "Alice grocery list",
        "body": "milk, eggs, lab-secret-alice-note",
        "visibility": "private",
    },
    {
        "id": 2,
        "owner": "bob",
        "title": "Bob payroll draft",
        "body": "dummy payroll token lab-secret-bob-note",
        "visibility": "private",
    },
    {
        "id": 3,
        "owner": "admin",
        "title": "Admin runbook",
        "body": "containment: disable LAB_MODE and rotate JWT_SECRET",
        "visibility": "private",
    },
]
