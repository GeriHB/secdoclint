from pathlib import Path
import tempfile
import unittest

from secdoclint.config import Config
from secdoclint.scanner import scan_repository

class ScannerTests(unittest.TestCase)