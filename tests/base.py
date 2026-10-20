"""
Shared test setup, extracted from the ad-hoc verification scripts this
project has been using manually all along (temp SQLite DB, init_db(),
seed_admin(), Flask test_client(), login). Formalizing it here so future
changes can be regression-tested with `python3 -m unittest discover -s
tests` instead of a one-off script written and thrown away each time.

Deliberately uses the stdlib `unittest` module rather than pytest: this
project has no network access to install third-party packages in every
environment it might be checked out in, and `unittest` needs nothing
beyond the standard library, so `python3 -m unittest discover -s tests`
just works anywhere Python itself runs.
"""
import os
import tempfile
import unittest

import storage.db as db


class CyberGuardTestCase(unittest.TestCase):
    """
    Base class: gives each test its own throwaway SQLite DB (never touches
    the real cyberguardllm.db) with the schema initialized and the default
    admin user seeded, plus a logged-in Flask test client ready to use as
    self.client. Subclasses can add more setup in an overridden setUp() as
    long as they call super().setUp() first.
    """

    def setUp(self):
        self._tmp_db = tempfile.mktemp(suffix=".db")
        db.DB_PATH = self._tmp_db

        # webapp.app is imported lazily (not at module load time) so that
        # db.DB_PATH above is already patched before app.py's own module-
        # level code (if any) touches the database.
        import importlib
        import webapp.app as app_mod
        importlib.reload(app_mod)
        self.app_mod = app_mod

        app_mod.init_db()

        from auth.auth import seed_admin
        seed_admin()

        app_mod.app.config["TESTING"] = True
        self.client = app_mod.app.test_client()
        login_resp = self.client.post(
            "/login", data={"username": "admin", "password": "admin"}, follow_redirects=True
        )
        assert login_resp.status_code == 200, f"test login failed: {login_resp.status_code}"

    def tearDown(self):
        try:
            os.remove(self._tmp_db)
        except OSError:
            pass

    def get_conn(self):
        return db.get_conn()
