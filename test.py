#!/usr/bin/python3
# Author:   @AgbaD || @agba_dr3

from app import app
import unittest


class AuthTest(unittest.TestCase):

    def test_get_login(self):
        tester = app.test_client(self)
        response = tester.get("/login")
        self.assertEqual(response.status_code, 400)

    def test_server(self):
        tester = app.test_client(self)
        response = tester.get("/")
        self.assertEqual(response.status_code, 200)


if __name__ == "__main__":
    unittest.main()
