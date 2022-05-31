"""Tests for the bonus subtask."""

import os
import tempfile
import urllib.request

from .base import TestCaseBase

class ExportFunctionTestCases(TestCaseBase):
    def test_example(self):
        actual = self.run_command(["export-functions", "./examples/3/3.dll"], 0)
        expected = self.get_answer("tests/4/1")

        self.assertSetSame(
            self.parse_set(actual),
            self.parse_set(expected)
        )

    def test_large_dll(self):
        actual = self.run_command(["export-functions", "./examples/4/4.dll"], 0)
        expected = self.get_answer("tests/4/2")

        self.assertSetSame(
            self.parse_set(actual),
            self.parse_set(expected)
        )
